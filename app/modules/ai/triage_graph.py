"""
Incident triage agent — LangGraph ReAct agent with time-anchored evidence + command suggestions.

Entry point: run_triage(incident_id) -> dict

Flow:
  1. load_policy    — fetch incident + server, resolve autonomy level, bind tools
  2. pre_fetch      — parallel context build (server state, metrics, logs, related events)
  3. agent stream   — create_react_agent with astream_events; tokens emitted to WS in real-time
  4. parse_output   — extract structured fields + command suggestions from JSON block in response
  5. persist        — save to ai_analysis + create ai_command rows
"""
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from app.core.database import get_database
from app.core.events import event_bus
from app.modules.ai.llm import get_chat_model
from app.modules.ai.policy import bind_tools_for_server
from app.modules.ai.analysis_store import save_analysis
from app.modules.ai.command_store import create_commands
from app.modules.ai.context_builder import build_incident_context


TRIAGE_SYSTEM_PROMPT = """You are a Senior Security Operations Center (SOC) Analyst with deep expertise in threat detection, incident response, and infrastructure diagnostics. Your job is to produce a thorough, evidence-driven triage report that gives the on-call operator a complete picture of what happened, why it matters, and exactly what to do about it.

## You Already Have Rich Context

The user message includes a pre-fetched snapshot:
- **Server Profile** — hostname, OS, live status, open incident count, business hours
- **Metrics at Event Time** — CPU/RAM/disk readings in the ±15 minute window around the event
- **Surrounding Logs** — log lines in the ±5 minute window around the event
- **Related Incidents & Anomalies** — other events on the same server in the last 24h

Use this context as your primary evidence. Use the available tools to **drill deeper** when you need more detail — for example:
- If you see a suspicious log line and want to check whether it's a recurring pattern
- If you want to compare current metrics to the state right now (get_server_metrics)
- If you want to look further back in time (get_recent_logs, get_related_incidents)
- If you need the rule definition or remediation script details (get_rule, get_incident)

Do NOT repeat calls you can answer from the pre-fetched context.

## Required Analysis Sections

Write your analysis in Markdown with EXACTLY these sections (use ### for each):

### Server State at Event Time
Describe the server's health at the moment the event fired. Include specific numbers from the metrics table (CPU%, RAM%, disk%). Note whether the event fired during business hours or off-hours. Comment on any other incidents or anomalies that were concurrent.

### What Happened
A clear chronological narrative of the event using timestamps from the log data provided. Quote specific log lines as evidence. Identify the trigger log message that fired the detection rule.

### Why It Matters
Assess the operational impact: What service or functionality is at risk? Could this be a precursor to a larger incident (privilege escalation, lateral movement, data exfiltration)? How urgently does this need attention?

### Probable Root Cause
State your best hypothesis with a confidence rating (0–100%). List 2–3 alternative hypotheses ranked by likelihood. Reference specific log lines or metric anomalies that support or contradict each hypothesis.

### Current State (Right Now)
Based on the latest metrics snapshot and any tool calls you made: is the issue still ongoing or has it resolved itself? Is the server stable?

### Investigation Evidence
List the key evidence items (log lines, metric spikes, rule match details, related incidents) with their timestamps. This is the "cite your sources" section.

### Recommended Actions
Two sub-sections:
1. **Automated commands** — diagnostic or remediation commands the platform can run over SSH/WinRM (non-interactive, no sudo). Mark each with risk level.
2. **Manual operator steps** — anything requiring sudo, interactive input, or elevated access. These go into manual_commands.

### Open Questions
List 2–3 things the analyst should verify that you could not determine from available data.

---

At the very end of your response, output a ```json block with this EXACT structure:
```json
{
  "summary": "one-sentence headline of what happened",
  "severity_assessment": "critical|high|medium|low — reason",
  "root_cause_hypothesis": "brief root cause",
  "confidence": 0.85,
  "impact_now": "current state of the server",
  "suggested_commands": [
    {
      "command": "exact shell/powershell command",
      "os_type": "linux",
      "purpose": "one sentence — why this command",
      "risk_level": "low|medium|high",
      "expected_outcome": "what we expect to see if it worked",
      "is_read_only": true
    }
  ],
  "manual_commands": [
    {
      "command": "sudo journalctl -u ssh --since '10 min ago'",
      "purpose": "one sentence — what this checks",
      "note": "requires sudo / interactive terminal"
    }
  ]
}
```

## Command Suggestion Rules

**suggested_commands** — auto-executed by the platform over non-interactive SSH (up to 6):
- NEVER use sudo — SSH is non-interactive; sudo always fails without a TTY
- Match os_type to the server's OS
- Prefer is_read_only=true diagnostic commands first
- Only suggest mutating commands when root cause is confirmed
- risk_level: low=diagnostic, medium=service restart/config, high=blocking/firewall/user changes
- If none, use suggested_commands: []

**manual_commands** — copy-paste for the operator in an interactive terminal (up to 5):
- Use for anything requiring sudo, interactive confirmation, or elevated privileges
- Always include a "note" explaining WHY it must be run manually
- If none, use manual_commands: []
"""


def _extract_json_block(text: str) -> Optional[dict]:
    matches = list(re.finditer(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL))
    if not matches:
        return None
    try:
        return json.loads(matches[-1].group(1))
    except Exception:
        return None


def _extract_final_text(messages: list) -> str:
    for msg in reversed(messages):
        if hasattr(msg, "content") and msg.content and not getattr(msg, "tool_calls", None):
            content = msg.content
            if isinstance(content, list):
                return "\n".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in content).strip()
            return str(content).strip()
    return ""


def _extract_pending_ids(messages: list) -> list:
    ids = []
    for msg in messages:
        content = getattr(msg, "content", "")
        if isinstance(content, str):
            try:
                data = json.loads(content)
                if isinstance(data, dict) and "pending_action_id" in data:
                    ids.append(data["pending_action_id"])
            except Exception:
                pass
    return ids


def _emit_ws(server_id: str, event_type: str, payload: dict):
    try:
        event_bus.emit(f"servers.{server_id}.ai", event_type, payload)
    except Exception:
        pass
    try:
        event_bus.emit("ai_actions", event_type, payload)
    except Exception:
        pass


async def run_triage(incident_id: str) -> dict:
    """
    Run the triage agent for an incident. Returns a dict with:
      analysis_id, run_id, markdown, summary, suggested_command_ids,
      pending_action_ids, confidence, analyzed_at
    """
    db = get_database()
    run_id = str(uuid.uuid4())[:8]
    t0 = time.monotonic()

    # 1. Load policy — fetch incident + server
    server: dict = {}
    incident_doc: dict = {}
    detected_at: datetime = datetime.now(timezone.utc)
    try:
        inc = await db["incidents"].find_one({"_id": ObjectId(incident_id)})
        if inc:
            inc["_id"] = str(inc["_id"])
            incident_doc = inc
            detected_at = inc.get("detected_at") or datetime.now(timezone.utc)
            if detected_at.tzinfo is None:
                detected_at = detected_at.replace(tzinfo=timezone.utc)
            if inc.get("server_id"):
                srv = await db["servers"].find_one({"_id": ObjectId(str(inc["server_id"]))})
                if srv:
                    srv["_id"] = str(srv["_id"])
                    server = srv
    except Exception:
        pass

    detected_at_iso = detected_at.isoformat()
    tools = bind_tools_for_server(server, run_id)
    model = get_chat_model()
    server_id = server.get("_id", "")

    # 2. Pre-fetch context in parallel
    try:
        ctx_block = await build_incident_context(incident_id, incident_doc)
    except Exception as e:
        ctx_block = f"_Context pre-fetch failed: {e}_"

    # 3. Build initial user message with pre-fetched context
    user_message = (
        f"Investigate incident **{incident_id}** on server "
        f"**{server.get('hostname', 'unknown')}** "
        f"(server_id={server_id}, os={server.get('os_type', 'linux')}).\n\n"
        f"The incident fired at **{detected_at_iso}** (UTC).\n\n"
        f"---\n\n{ctx_block}\n\n---\n\n"
        f"Using this context and any additional tool calls needed, produce the full analysis "
        f"following the format in your system prompt. "
        f"End with the ```json block."
    )

    # 4. Agent stream — emit tokens to WS, collect final messages
    agent = create_react_agent(model=model, tools=tools, prompt=TRIAGE_SYSTEM_PROMPT)
    final_messages: list = []
    turn_count = 0
    # Fallback: accumulate all streamed tokens in case on_chain_end doesn't fire cleanly
    stream_buffer: list[str] = []

    _emit_ws(server_id, "ai_analysis_token", {
        "run_id": run_id, "source_type": "incident", "source_id": incident_id, "token": ""
    })

    try:
        async for ev in agent.astream_events(
            {"messages": [HumanMessage(content=user_message)]},
            version="v2",
            config={"recursion_limit": 25},
        ):
            etype = ev.get("event", "")

            if etype == "on_chat_model_stream":
                chunk = ev.get("data", {}).get("chunk")
                token_text = ""
                if chunk is not None and hasattr(chunk, "content"):
                    c = chunk.content
                    if isinstance(c, str):
                        token_text = c
                    elif isinstance(c, list):
                        try:
                            token_text = "".join(
                                p.get("text", "") if isinstance(p, dict) else str(p)
                                for p in c
                            )
                        except Exception:
                            token_text = ""
                if token_text:
                    stream_buffer.append(token_text)
                    _emit_ws(server_id, "ai_analysis_token", {
                        "run_id": run_id,
                        "source_type": "incident",
                        "source_id": incident_id,
                        "token": token_text,
                    })

            elif etype == "on_chat_model_end":
                turn_count += 1
                # Insert a paragraph break between agent turns so reasoning phases
                # don't smoosh together ("Let me check X" + "Now let me check Y" → two lines)
                if stream_buffer and not stream_buffer[-1].endswith("\n\n"):
                    separator = "\n\n"
                    stream_buffer.append(separator)
                    _emit_ws(server_id, "ai_analysis_token", {
                        "run_id": run_id,
                        "source_type": "incident",
                        "source_id": incident_id,
                        "token": separator,
                    })

            elif etype == "on_chain_end":
                # Accept any chain_end that carries messages; keep the one with most (outermost graph)
                output = ev.get("data", {}).get("output")
                if isinstance(output, dict):
                    msgs = output.get("messages", [])
                    if len(msgs) > len(final_messages):
                        final_messages = msgs

    except Exception as e:
        import traceback
        print(f"[triage] agent error for {incident_id}: {type(e).__name__}: {e}")
        traceback.print_exc()

    # Fallback: if on_chain_end never delivered messages, reconstruct from the stream buffer
    if not final_messages and stream_buffer:
        from langchain_core.messages import AIMessage
        final_messages = [AIMessage(content="".join(stream_buffer))]

    print(f"[triage] {incident_id} captured: final_messages={len(final_messages)} stream_buffer_chars={sum(len(s) for s in stream_buffer)}")

    elapsed = time.monotonic() - t0
    print(f"[ai_triage] incident={incident_id} run={run_id} elapsed={elapsed:.2f}s turns={turn_count}")

    # 5. Parse structured output
    #
    # Two sources of truth:
    #   A) final_messages — clean agent output captured from on_chain_end (may be empty
    #      if the event didn't fire correctly or the agent was truncated by recursion_limit)
    #   B) stream_buffer  — every token the model emitted, including intermediate reasoning
    #      + the final answer + the JSON block at the very end; always complete
    #
    # Strategy:
    #   - Display text: prefer A (cleaner), fall back to B
    #   - JSON / commands: try A first, then B (B always has the full output)
    pending_action_ids = _extract_pending_ids(final_messages)

    raw_text_messages = _extract_final_text(final_messages)
    full_stream = "".join(stream_buffer)

    # Choose display text
    if raw_text_messages and "need more steps" not in raw_text_messages.lower()[:80]:
        raw_text = raw_text_messages
    elif full_stream:
        raw_text = full_stream
    else:
        raw_text = raw_text_messages  # error text is still better than nothing

    # Extract JSON — try the clean message first, then the full stream as fallback
    # (stream always contains the last ```json``` block the model wrote)
    parsed = (
        _extract_json_block(raw_text_messages)
        or _extract_json_block(full_stream)
        or {}
    )

    suggestions = parsed.get("suggested_commands", [])
    manual_commands = parsed.get("manual_commands", [])
    summary = parsed.get("summary", (raw_text[:200] if raw_text else "Analysis complete."))
    confidence = float(parsed.get("confidence", 0.0))

    print(
        f"[triage] {incident_id}: json_found={bool(parsed)} "
        f"suggestions={len(suggestions)} manual={len(manual_commands)} "
        f"msg_chars={len(raw_text_messages)} stream_chars={len(full_stream)}"
    )
    structured = {
        "severity_assessment": parsed.get("severity_assessment", ""),
        "root_cause_hypothesis": parsed.get("root_cause_hypothesis", ""),
        "impact_now": parsed.get("impact_now", ""),
        "manual_commands": manual_commands,
    }

    markdown = f"## AI Triage Analysis\n\n{raw_text}\n\n---\n*Run ID: {run_id} · Incident: {incident_id}*"

    from app.core.config import settings

    # 6. Persist
    analysis_id = await save_analysis(
        run_id=run_id,
        analysis_type="incident_triage",
        source_type="incident",
        source_id=incident_id,
        server_id=server_id,
        summary=summary,
        markdown=markdown,
        confidence=confidence,
        structured={**structured, "suggested_command_ids": []},
        anchored_at=detected_at,
        window_minutes=5,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.LLM_MODEL,
    )

    command_ids = await create_commands(
        analysis_id=analysis_id,
        run_id=run_id,
        source_type="incident",
        source_id=incident_id,
        server_id=server_id,
        suggestions=suggestions,
    )

    if command_ids:
        await db["ai_analysis"].update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": {"structured.suggested_command_ids": command_ids}},
        )

    # Emit completion signal
    _emit_ws(server_id, "ai_analysis_complete", {
        "run_id": run_id,
        "source_type": "incident",
        "source_id": incident_id,
        "analysis_id": analysis_id,
    })

    return {
        "analysis_id": analysis_id,
        "run_id": run_id,
        "markdown": markdown,
        "summary": summary,
        "confidence": confidence,
        "suggested_command_ids": command_ids,
        "manual_commands": manual_commands,
        "pending_action_ids": pending_action_ids,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
