"""
Anomaly triage agent — LangGraph ReAct agent for Tier 2 observations.

Entry point: run_anomaly_triage(observation_id) -> dict

Flow:
  1. load_policy  — fetch observation + server, resolve autonomy level, bind tools
  2. pre_fetch    — parallel context build (server state, metrics, logs, related events)
  3. agent stream — create_react_agent with astream_events; tokens emitted to WS in real-time
  4. parse_output — extract structured fields + command suggestions from JSON block
  5. persist      — save to ai_analysis + create ai_command rows
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
from app.modules.ai.context_builder import build_anomaly_context


ANOMALY_SYSTEM_PROMPT = """You are a Senior Security Operations Center (SOC) Analyst specializing in anomaly detection and behavioral analysis. You are reviewing a Tier 2 heuristic anomaly — flagged by pattern-matching, keyword scoring, or time-of-day analysis, NOT by a deterministic signature rule. Your goal is to determine whether this represents a real threat and give the operator a complete, actionable report.

## You Already Have Rich Context

The user message includes a pre-fetched snapshot:
- **Server Profile** — hostname, OS, live status, open incident count, business hours
- **Metrics at Event Time** — CPU/RAM/disk readings in the ±15 minute window around when the anomaly first appeared
- **Surrounding Logs** — log lines in the ±5 minute window around first detection
- **Related Incidents & Anomalies** — other events on the same server in the last 24h

Use this context as your primary evidence. Use the available tools to **drill deeper** when needed:
- `get_anomaly` — for full observation details including score, reasons, all occurrence timestamps
- `get_pattern_history` — to check how long this pattern has existed on the server
- `get_logs_around` — to look at a different time window than the pre-fetched one
- `get_recent_logs` — for current state assessment
- `get_server_metrics` — for current metric snapshot
- `get_related_incidents` / `get_related_anomalies` — for broader pattern over multiple days

Do NOT repeat calls you can answer from the pre-fetched context.

## Required Analysis Sections

Write your analysis in Markdown with EXACTLY these sections (use ### for each):

### Server State at Event Time
Describe the server's health when the anomaly was first detected. Include specific metric numbers (CPU%, RAM%, disk%). Was this during business hours or off-hours? Were any other incidents or anomalies active at the same time?

### What Happened
A clear narrative of the anomaly: what triggered it, how many times has this pattern appeared, when was it first vs. last seen. Quote specific log lines from the pre-fetched surrounding logs or tool output as evidence.

### Signal Quality Assessment
Rate the signal: **suspicious**, **noisy**, **benign**, or **needs-more-context**. Explain why. Consider:
- Is this a known-noisy pattern (cron jobs, health checks, expected batch processes)?
- Does the log message contain indicators of compromise (unusual usernames, unknown IPs, off-hours logins)?
- Is the occurrence count climbing (worsening) or flat (stable)?
- Were concurrent incidents or anomalies fired, suggesting correlated activity?

### Why It Matters (or Doesn't)
Assess the operational significance. What is the worst-case interpretation? What is the benign interpretation? How confident are you in each?

### Probable Root Cause
State your best hypothesis with a confidence rating (0–100%). List 2–3 alternative hypotheses ranked by likelihood. Reference specific log lines or metric anomalies that support or contradict each.

### Current State (Right Now)
Based on the latest metrics snapshot and any tool calls you made: is the pattern still active? Has the server's health changed since the anomaly first fired?

### Investigation Evidence
List the key evidence items with timestamps: log lines, metric readings, occurrence count, score breakdown, related events.

### Recommended Actions
Two sub-sections:
1. **Automated commands** — diagnostic commands the platform can run over SSH/WinRM (no sudo, non-interactive). Mark each with risk level.
2. **Manual operator steps** — anything requiring sudo, interactive input, or elevated access.

### Promotion Decision
State your recommendation: **promote_to_incident**, **dismiss**, or **monitor** (keep watching). Justify the choice with reference to evidence above.

### Open Questions
List 2–3 things the analyst should verify that you could not determine from available data.

---

At the very end of your response, output a ```json block with this EXACT structure:
```json
{
  "summary": "one-sentence headline of the anomaly",
  "severity_assessment": "high|medium|low — reason",
  "root_cause_hypothesis": "brief hypothesis",
  "confidence": 0.75,
  "impact_now": "current state of the server",
  "promotion_recommendation": "promote_to_incident|dismiss|monitor",
  "suggested_commands": [
    {
      "command": "exact shell/powershell command",
      "os_type": "linux",
      "purpose": "one sentence — why this command",
      "risk_level": "low|medium|high",
      "expected_outcome": "what we expect to see",
      "is_read_only": true
    }
  ],
  "manual_commands": [
    {
      "command": "sudo cat /var/log/auth.log | tail -50",
      "purpose": "what this checks",
      "note": "requires sudo / interactive terminal"
    }
  ]
}
```

## Command Rules
- **suggested_commands** (auto-executed by platform, up to 4): no sudo, direct commands, non-interactive
- **manual_commands** (operator copy-pastes, up to 3): sudo ok, interactive ok — always include "note"
- Prefer read-only diagnostics first
- NEVER echo attacker-controlled log data into a command without proper quoting
- If no commands needed, use []
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


async def run_anomaly_triage(observation_id: str) -> dict:
    """
    Run the triage agent for an anomaly observation. Returns a dict with:
      analysis_id, run_id, markdown, summary, promotion_recommendation,
      suggested_command_ids, pending_action_ids, confidence, analyzed_at
    """
    db = get_database()
    run_id = str(uuid.uuid4())[:8]
    t0 = time.monotonic()

    # 1. Load policy — fetch observation + server
    server: dict = {}
    obs_doc: dict = {}
    first_seen_at: datetime = datetime.now(timezone.utc)
    try:
        obs = await db["log_observations"].find_one({"_id": ObjectId(observation_id)})
        if obs:
            obs["_id"] = str(obs["_id"])
            obs_doc = obs
            first_seen_at = obs.get("first_seen_at") or obs.get("detected_at") or datetime.now(timezone.utc)
            if first_seen_at.tzinfo is None:
                first_seen_at = first_seen_at.replace(tzinfo=timezone.utc)
            if obs.get("server_id"):
                srv = await db["servers"].find_one({"_id": ObjectId(str(obs["server_id"]))})
                if srv:
                    srv["_id"] = str(srv["_id"])
                    server = srv
    except Exception:
        pass

    first_seen_iso = first_seen_at.isoformat()
    tools = bind_tools_for_server(server, run_id)
    model = get_chat_model()
    server_id = server.get("_id", "")

    # 2. Pre-fetch context in parallel
    try:
        ctx_block = await build_anomaly_context(observation_id, obs_doc)
    except Exception as e:
        ctx_block = f"_Context pre-fetch failed: {e}_"

    # 3. Build initial user message with pre-fetched context
    user_message = (
        f"Triage anomaly observation **{observation_id}** on server "
        f"**{server.get('hostname', 'unknown')}** "
        f"(server_id={server_id}, os={server.get('os_type', 'linux')}).\n\n"
        f"The pattern was first detected at **{first_seen_iso}** (UTC).\n\n"
        f"---\n\n{ctx_block}\n\n---\n\n"
        f"Using this context and any additional tool calls needed, produce the full analysis "
        f"following the format in your system prompt. "
        f"End with the ```json block."
    )

    # 4. Agent stream — emit tokens to WS, collect final messages
    agent = create_react_agent(model=model, tools=tools, prompt=ANOMALY_SYSTEM_PROMPT)
    final_messages: list = []
    turn_count = 0
    # Fallback: accumulate all streamed tokens in case on_chain_end doesn't fire cleanly
    stream_buffer: list[str] = []

    _emit_ws(server_id, "ai_analysis_token", {
        "run_id": run_id, "source_type": "anomaly", "source_id": observation_id, "token": ""
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
                        "source_type": "anomaly",
                        "source_id": observation_id,
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
                        "source_type": "anomaly",
                        "source_id": observation_id,
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
        print(f"[anomaly_triage] agent error for {observation_id}: {type(e).__name__}: {e}")
        traceback.print_exc()

    # Fallback: if on_chain_end never delivered messages, reconstruct from the stream buffer
    if not final_messages and stream_buffer:
        from langchain_core.messages import AIMessage
        final_messages = [AIMessage(content="".join(stream_buffer))]

    print(f"[anomaly_triage] {observation_id} captured: final_messages={len(final_messages)} stream_buffer_chars={sum(len(s) for s in stream_buffer)}")

    elapsed = time.monotonic() - t0
    print(f"[ai_anomaly] observation={observation_id} run={run_id} elapsed={elapsed:.2f}s turns={turn_count}")

    # 5. Parse structured output
    #
    # Two sources:
    #   A) final_messages — clean agent output from on_chain_end (may be empty)
    #   B) stream_buffer  — complete stream including intermediate reasoning + final JSON block
    #
    # Display text: prefer A (cleaner), fall back to B
    # JSON / commands: try A first, then B (B always has the complete output)
    pending_action_ids = _extract_pending_ids(final_messages)

    raw_text_messages = _extract_final_text(final_messages)
    full_stream = "".join(stream_buffer)

    # Choose display text
    if raw_text_messages and "need more steps" not in raw_text_messages.lower()[:80]:
        raw_text = raw_text_messages
    elif full_stream:
        raw_text = full_stream
    else:
        raw_text = raw_text_messages

    # Extract JSON — try clean message first, then full stream as fallback
    parsed = (
        _extract_json_block(raw_text_messages)
        or _extract_json_block(full_stream)
        or {}
    )

    summary = parsed.get("summary", (raw_text[:200] if raw_text else "Analysis complete."))
    confidence = float(parsed.get("confidence", 0.0))
    promotion_recommendation = parsed.get("promotion_recommendation", "monitor")
    suggestions = parsed.get("suggested_commands", [])
    manual_commands = parsed.get("manual_commands", [])

    print(
        f"[anomaly_triage] {observation_id}: json_found={bool(parsed)} "
        f"suggestions={len(suggestions)} manual={len(manual_commands)} "
        f"msg_chars={len(raw_text_messages)} stream_chars={len(full_stream)}"
    )
    structured = {
        "severity_assessment": parsed.get("severity_assessment", ""),
        "root_cause_hypothesis": parsed.get("root_cause_hypothesis", ""),
        "impact_now": parsed.get("impact_now", ""),
        "promotion_recommendation": promotion_recommendation,
        "manual_commands": manual_commands,
    }

    markdown = f"## AI Anomaly Analysis\n\n{raw_text}\n\n---\n*Run ID: {run_id} · Observation: {observation_id}*"

    from app.core.config import settings

    # 6. Persist
    analysis_id = await save_analysis(
        run_id=run_id,
        analysis_type="anomaly_triage",
        source_type="anomaly",
        source_id=observation_id,
        server_id=server_id,
        summary=summary,
        markdown=markdown,
        confidence=confidence,
        structured={**structured, "suggested_command_ids": []},
        anchored_at=first_seen_at,
        window_minutes=5,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.LLM_MODEL,
    )

    command_ids = await create_commands(
        analysis_id=analysis_id,
        run_id=run_id,
        source_type="anomaly",
        source_id=observation_id,
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
        "source_type": "anomaly",
        "source_id": observation_id,
        "analysis_id": analysis_id,
    })

    return {
        "analysis_id": analysis_id,
        "run_id": run_id,
        "markdown": markdown,
        "summary": summary,
        "confidence": confidence,
        "promotion_recommendation": promotion_recommendation,
        "suggested_command_ids": command_ids,
        "manual_commands": manual_commands,
        "pending_action_ids": pending_action_ids,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
