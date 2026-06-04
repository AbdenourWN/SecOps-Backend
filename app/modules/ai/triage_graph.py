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
from app.core.constants import (
    Collections, WSEvent, WSTopic, AnalysisType, SourceType,
    NotificationType, NotificationCategory, NotificationSeverity,
)
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

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
from app.modules.ai.tools_mutate import clear_pending_actions_for_source
from app.modules.notifications.feed import notify


TRIAGE_SYSTEM_PROMPT = """You are a Senior Security Operations Center (SOC) Analyst with deep expertise in threat detection, incident response, and infrastructure diagnostics. Your job is to produce a thorough, evidence-driven triage report that gives the on-call operator a complete picture of what happened, why it matters, and exactly what to do about it.

## Working Style (read first — applies to everything below)

- **Quote logs and metrics verbatim.** When you cite a specific log line, IP, username, timestamp, or metric number, copy it from the data provided. Reasonable inferences and hypotheses ARE welcome — just don't invent concrete specifics (a username, IP, port, etc.) that don't appear in the data.
- **Be honest about uncertainty.** When evidence is thin, say so and put unanswered questions in **Open Questions**. A confident "I don't know yet" is more useful than a fabricated certainty.
- **Use tools deliberately.** Call a tool when you genuinely need a fact you don't already have. The pre-fetched context covers most cases — most triages need 1–4 targeted tool calls.
- **Write for a busy on-call operator.** Tight, evidence-dense prose. Every sentence should add a fact, a hypothesis, or an action.
- **Always produce command suggestions.** Even if the server is offline, in a degraded state, or the incident appears resolved, the operator wants ready-to-run diagnostic/remediation commands they can save for when the server is reachable again. Suggested commands and manual commands are NEVER "skip because the server is down" — only skip if the command itself genuinely doesn't apply to the diagnosed root cause.

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

Write your analysis in Markdown with EXACTLY these sections (use ### for each).
**Use bullet points (`-`) in every section.** No long paragraphs. Each bullet = one fact, one hypothesis, or one action. Include all necessary information but keep each bullet tight and scannable.

### Server State at Event Time
- CPU / RAM / disk readings at event time (specific numbers)
- Business-hours vs off-hours
- Any concurrent incidents or anomalies on the same server

### What Happened
- Chronological bullets with timestamps from the log data
- Verbatim quote of the trigger log line that fired the rule
- Any directly related log lines around it (also quoted)

### Why It Matters
- Service or functionality at risk
- Escalation potential (privilege escalation, lateral movement, data exfiltration, etc.) — only list those that fit the evidence
- Urgency level + one-line justification

### Probable Root Cause
- **Lead hypothesis:** one line + confidence %
- **Alternatives** (2–3 bullets, ranked by likelihood) — each with a one-line reason citing specific evidence

### Current State (Right Now)
- Ongoing vs resolved
- Server stability indicator
- Metric trend since the event (one bullet)

### Investigation Evidence
- Bulleted list of key evidence items, each with its timestamp and a verbatim fragment (log line, metric number, rule field, related incident ID)
- This is the "cite your sources" section — be specific

### Open Questions
- 2–3 bullets — specific facts the analyst should verify that you could not determine from the available data

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

## Status-Change Tools (only present when the server is set to `suggest` autonomy)

If the agent has been given any of `dismiss_anomaly`, `promote_anomaly`, or `mark_incident_false_positive` in its toolset, those are **mutation tools**. They do NOT execute immediately — calling one queues a row in `ai_actions` that an operator must approve before the change happens.

When (and only when) to call one of these:

- **`mark_incident_false_positive(incident_id, reason)`** — call this if your investigation reaches a confident verdict that this incident is **benign** (e.g. an expected maintenance event, a legitimate sysadmin login, a known test signature). Provide the current incident_id and a one-line reason. Do NOT call it on the basis of "looks innocuous" — only when the evidence in the data given to you actively rules out malicious causes.

**You must never silently use mutation tools.** Always explicitly explain in your markdown narrative WHY you are queuing the status change — the operator reads your reasoning to decide whether to approve.

**Important:** Calling a mutation tool does NOT replace producing the final analysis. After (or before) the tool call, you still must produce the full markdown sections AND the trailing ```json``` block with `suggested_commands` and `manual_commands` as usual. If you decide no diagnostic commands are needed (because the incident is a false positive), use empty arrays — do not skip the JSON block.

If none of these tools are in your toolset, this server is in `read_only` mode — do not mention status changes; just produce the analysis and command suggestions.

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
        event_bus.emit(WSTopic.AI_ACTIONS, event_type, payload)
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
        inc = await db[Collections.INCIDENTS].find_one({"_id": ObjectId(incident_id)})
        if inc:
            inc["_id"] = str(inc["_id"])
            incident_doc = inc
            detected_at = inc.get("detected_at") or datetime.now(timezone.utc)
            if detected_at.tzinfo is None:
                detected_at = detected_at.replace(tzinfo=timezone.utc)
            if inc.get("server_id"):
                srv = await db[Collections.SERVERS].find_one({"_id": ObjectId(str(inc["server_id"]))})
                if srv:
                    srv["_id"] = str(srv["_id"])
                    server = srv
    except Exception:
        pass

    detected_at_iso = detected_at.isoformat()

    # Re-analysis hygiene: wipe any stale PENDING ai_actions rows from a prior
    # run on this incident. Approved/rejected rows stay as audit trail; only
    # the still-pending ones (which the operator hadn't yet acted on) get
    # superseded by whatever the new run produces.
    try:
        deleted = await clear_pending_actions_for_source("incident", incident_id)
        if deleted:
            logger.info("[triage] cleared %d stale pending ai_actions row(s) for incident %s", deleted, incident_id)
    except Exception as e:
        logger.warning("[triage] clear_pending_actions failed for incident %s: %s", incident_id, e)

    tools = bind_tools_for_server(server, run_id, source_type=SourceType.INCIDENT, source_id=incident_id)
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
    # Snapshot of stream_buffer length at the start of each model turn — lets the
    # on_chat_model_end handler detect whether the model actually streamed (token
    # events fired) or just dropped a full response in the end event (non-streaming
    # providers). When the buffer didn't grow during the turn, we harvest content
    # from on_chat_model_end so the analysis isn't silently empty.
    buffer_size_at_turn_start = 0

    _emit_ws(server_id, WSEvent.AI_ANALYSIS_TOKEN, {
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
                    _emit_ws(server_id, WSEvent.AI_ANALYSIS_TOKEN, {
                        "run_id": run_id,
                        "source_type": "incident",
                        "source_id": incident_id,
                        "token": token_text,
                    })

            elif etype == "on_chat_model_end":
                turn_count += 1
                # Robustness: some models (or some langchain providers) don't emit
                # on_chat_model_stream chunks at all — they only fire on_chat_model_end
                # with the full message. When stream_buffer didn't grow during this
                # turn, harvest the content from data.output and push it as one
                # synthetic token so the frontend sees the analysis.
                streamed_this_turn = len(stream_buffer) > buffer_size_at_turn_start
                if not streamed_this_turn:
                    output = ev.get("data", {}).get("output")
                    output_content = ""
                    if output is not None:
                        raw = getattr(output, "content", None)
                        if isinstance(raw, str):
                            output_content = raw
                        elif isinstance(raw, list):
                            try:
                                output_content = "".join(
                                    p.get("text", "") if isinstance(p, dict) else str(p)
                                    for p in raw
                                )
                            except Exception:
                                output_content = ""
                    if output_content:
                        _emit_ws(server_id, WSEvent.AI_ANALYSIS_TOKEN, {
                            "run_id": run_id,
                            "source_type": "incident",
                            "source_id": incident_id,
                            "token": output_content,
                        })
                        stream_buffer.append(output_content)
                # Insert a paragraph break between agent turns so reasoning phases
                # don't smoosh together ("Let me check X" + "Now let me check Y" → two lines)
                if stream_buffer and not stream_buffer[-1].endswith("\n\n"):
                    separator = "\n\n"
                    stream_buffer.append(separator)
                    _emit_ws(server_id, WSEvent.AI_ANALYSIS_TOKEN, {
                        "run_id": run_id,
                        "source_type": "incident",
                        "source_id": incident_id,
                        "token": separator,
                    })
                # Snapshot for the next turn
                buffer_size_at_turn_start = len(stream_buffer)

            elif etype == "on_chain_end":
                # Accept any chain_end that carries messages; keep the one with most (outermost graph)
                output = ev.get("data", {}).get("output")
                if isinstance(output, dict):
                    msgs = output.get("messages", [])
                    if len(msgs) > len(final_messages):
                        final_messages = msgs

    except Exception as e:
        import traceback
        logger.error("[triage] agent error for %s: %s: %s", incident_id, type(e).__name__, e)
        traceback.print_exc()

    # Fallback: if on_chain_end never delivered messages, reconstruct from the stream buffer
    if not final_messages and stream_buffer:
        from langchain_core.messages import AIMessage
        final_messages = [AIMessage(content="".join(stream_buffer))]

    logger.debug("[triage] %s captured: final_messages=%d stream_buffer_chars=%d", incident_id, len(final_messages), sum(len(s) for s in stream_buffer))

    elapsed = time.monotonic() - t0
    logger.info("[ai_triage] incident=%s run=%s elapsed=%.2fs turns=%s", incident_id, run_id, elapsed, turn_count)

    # If the agent produced nothing at all — no messages AND no streamed tokens
    # — surface the failure to the caller so the router returns 503 instead of
    # silently saving an empty analysis row.
    if not final_messages and not stream_buffer:
        _emit_ws(server_id, WSEvent.AI_ANALYSIS_COMPLETE, {
            "run_id": run_id,
            "source_type": "incident",
            "source_id": incident_id,
            "analysis_id": None,
            "error": "agent_produced_no_output",
        })
        await notify(
            type=NotificationType.AI_ANALYSIS_FAILED,
            category=NotificationCategory.AI,
            severity=NotificationSeverity.ERROR,
            title="Incident triage failed",
            body="The AI agent produced no output. Please try running the analysis again.",
            link=f"/incidents/{incident_id}",
            server_id=server_id,
            entity_type="incident",
            entity_id=incident_id,
        )
        raise RuntimeError(
            f"Triage agent produced no output for incident {incident_id} "
            f"(run {run_id}, elapsed {elapsed:.2f}s). Check the [triage] log lines above "
            f"for the underlying exception."
        )

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

    # Choose display text. Prefer the full streamed buffer because it contains
    # EVERY token the model emitted — including analysis sections produced in
    # the same AIMessage as a tool call. `_extract_final_text` only returns
    # messages with no tool_calls, which means it drops mid-stream sections
    # when the model interleaves analysis with tool use. The buffer is what
    # the user saw streaming, so the saved version should match that.
    if full_stream and "need more steps" not in full_stream.lower()[:80]:
        raw_text = full_stream
    elif raw_text_messages:
        raw_text = raw_text_messages
    else:
        raw_text = ""

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

    logger.debug(
        "[triage] %s: json_found=%s suggestions=%d manual=%d msg_chars=%d stream_chars=%d",
        incident_id, bool(parsed), len(suggestions), len(manual_commands),
        len(raw_text_messages), len(full_stream),
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
        analysis_type=AnalysisType.INCIDENT_TRIAGE,
        source_type=SourceType.INCIDENT,
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
        source_type=SourceType.INCIDENT,
        source_id=incident_id,
        server_id=server_id,
        suggestions=suggestions,
    )

    if command_ids:
        await db[Collections.AI_ANALYSIS].update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": {"structured.suggested_command_ids": command_ids}},
        )

    # Emit completion signal
    _emit_ws(server_id, WSEvent.AI_ANALYSIS_COMPLETE, {
        "run_id": run_id,
        "source_type": "incident",
        "source_id": incident_id,
        "analysis_id": analysis_id,
    })

    # In-app notification: the headline case — finished while the operator may
    # have navigated away; clicking it deep-links back to the incident.
    await notify(
        type=NotificationType.AI_ANALYSIS_READY,
        category=NotificationCategory.AI,
        severity=NotificationSeverity.SUCCESS,
        title="Incident triage ready",
        body=(summary or "AI analysis complete.")[:160],
        link=f"/incidents/{incident_id}",
        server_id=server_id,
        entity_type="incident",
        entity_id=incident_id,
    )

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
