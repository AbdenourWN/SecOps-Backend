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
from app.core.datetime_utils import utc_now
from app.core.events import event_bus
from app.modules.ai.llm import get_chat_model
from app.modules.ai.policy import bind_tools_for_server
from app.modules.ai.analysis_store import save_analysis
from app.modules.ai.command_store import create_commands
from app.modules.ai.context_builder import build_anomaly_context
from app.modules.ai.tools_mutate import clear_pending_actions_for_source
from app.modules.notifications.feed import notify


ANOMALY_SYSTEM_PROMPT = """You are a Senior Security Operations Center (SOC) Analyst specializing in anomaly detection and behavioral analysis. You are reviewing a Tier 2 heuristic anomaly — flagged by pattern-matching, keyword scoring, or time-of-day analysis, NOT by a deterministic signature rule. Your goal is to determine whether this represents a real threat and give the operator a complete, actionable report.

## Working Style (read first — applies to everything below)

- **Quote logs and metrics verbatim.** When you cite a specific log line, IP, username, timestamp, or metric number, copy it from the data provided. Reasonable inferences and hypotheses ARE welcome — just don't invent concrete specifics (a username, IP, port, etc.) that don't appear in the data.
- **Be honest about uncertainty.** When evidence is thin, say so and put unanswered questions in **Open Questions**. The heuristic signal here is fuzzy, so a confident "needs more context" is more useful than a fabricated certainty.
- **Use tools deliberately.** Call a tool when you genuinely need a fact you don't already have. The pre-fetched context covers most cases — most triages need 1–4 targeted tool calls.
- **Write for a busy on-call operator.** Tight, evidence-dense prose. Every sentence should add a fact, a hypothesis, or an action.
- **Always produce command suggestions.** Even if the server is offline, in a degraded state, or the anomaly appears resolved, the operator wants ready-to-run diagnostic commands they can save for when the server is reachable again. Suggested commands and manual commands are NEVER "skip because the server is down" — only skip if the command itself genuinely doesn't apply to your verdict (e.g. you're recommending dismiss).

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

Write your analysis in Markdown with EXACTLY these sections (use ### for each).
**Use bullet points (`-`) in every section.** No long paragraphs. Each bullet = one fact, one hypothesis, or one action. Include all necessary information but keep each bullet tight and scannable.

### Server State at Event Time
- CPU / RAM / disk readings when the anomaly was first detected (specific numbers)
- Business-hours vs off-hours
- Any concurrent incidents or anomalies on the same server

### What Happened
- What triggered the anomaly (the reasons / heuristic flags)
- First seen vs last seen timestamps + occurrence count
- Verbatim quote of a representative log line
- Any closely related log lines around it

### Signal Quality Assessment
- **Rating:** suspicious | noisy | benign | needs-more-context (pick one + one-line why)
- Is this a known-noisy pattern? (cron, health-check, batch — cite which)
- Does the log carry compromise indicators? (unusual user, unknown IP, off-hours) — cite the specific token
- Trend: occurrence count climbing or flat?
- Concurrent incidents/anomalies suggesting correlated activity?

### Why It Matters (or Doesn't)
- Worst-case interpretation + your confidence in it
- Benign interpretation + your confidence in it

### Probable Root Cause
- **Lead hypothesis:** one line + confidence %
- **Alternatives** (2–3 bullets, ranked by likelihood) — each with a one-line reason citing specific evidence

### Current State (Right Now)
- Pattern still active vs settled
- Server health vs at first detection (one bullet)
- Metric trend since the anomaly (one bullet)

### Investigation Evidence
- Bulleted list with timestamps + verbatim fragments (log lines, metric readings, score breakdown, related event IDs)

### Promotion Decision
- **Recommendation:** promote_to_incident | dismiss | monitor (one of these)
- One-line justification citing the strongest piece of evidence above

### Open Questions
- 2–3 bullets — specific facts the analyst should verify that you could not determine from the available data

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
  ],
  "suggestions": []
}
```

### Phase 28.5 — `suggestions` array (only on `suggest`-mode servers)

When this server is in `suggest` mode AND the anomaly evidence shows a
recurring pattern that the global rule library doesn't cover, you MAY
populate `suggestions[]` with one `create_server_rule` proposal. Anomalies
are by definition "things no rule fired on" — when the pattern is real and
recurring, promoting it into a server-scoped rule is the highest-value
follow-up. Approval auto-flips the server's `rule_library_mode` from
`global` to `both`.

```json
{
  "action": "create_server_rule",
  "reason": "Anomaly pattern Y has been observed N times on this server in the last <window>; cite the specific log fingerprints.",
  "name": "<rule name>",
  "pattern": "<Python regex>",
  "severity": "low|medium|high|critical",
  "action_level": 1|2|3,
  "description": "<short>",
  "os_type": "linux|windows|common",
  "tags": ["..."]
}
```

Only one suggestion per analysis (the most-justified one). Leave the array
empty when the anomaly is a one-off, when the cause is unclear, or when
your `promotion_recommendation` is already `dismiss`.

## Status-Change Tools (only present when the server is set to `suggest` autonomy)

If the agent has been given any of `dismiss_anomaly`, `promote_anomaly`, or `mark_incident_false_positive` in its toolset, those are **mutation tools**. They do NOT execute immediately — calling one queues a row in `ai_actions` that an operator must approve before the change happens.

When (and only when) to call one of these:

- **`dismiss_anomaly(observation_id, reason)`** — call this when your investigation concludes the anomaly is **benign / noisy** (known cron pattern, expected health-check, batch job, etc.) AND your `promotion_recommendation` is `dismiss`. Provide the current observation_id and a one-line reason.
- **`promote_anomaly(observation_id)`** — call this when the evidence strongly indicates a real threat AND your `promotion_recommendation` is `promote_to_incident`. The incident workflow (alerts, automation) only kicks in after operator approval.

Do NOT call `mark_incident_false_positive` from anomaly triage — that's for incident triage only.

**You must never silently use mutation tools.** Always explicitly explain in your markdown narrative WHY you are queuing the status change — the operator reads your reasoning to decide whether to approve.

**Important:** Calling a mutation tool does NOT replace producing the final analysis. You still must produce the full markdown sections AND the trailing ```json``` block with `suggested_commands`, `manual_commands`, and `promotion_recommendation`. The recommendation in the JSON should match what your tool call did.

If none of these tools are in your toolset, this server is in `read_only` mode — do not mention status changes in your output; just produce the analysis and command suggestions and let the operator act manually.

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
        event_bus.emit(WSTopic.AI_ACTIONS, event_type, payload)
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
        obs = await db[Collections.LOG_OBSERVATIONS].find_one({"_id": ObjectId(observation_id)})
        if obs:
            obs["_id"] = str(obs["_id"])
            obs_doc = obs
            first_seen_at = obs.get("first_seen_at") or obs.get("detected_at") or datetime.now(timezone.utc)
            if first_seen_at.tzinfo is None:
                first_seen_at = first_seen_at.replace(tzinfo=timezone.utc)
            if obs.get("server_id"):
                srv = await db[Collections.SERVERS].find_one({"_id": ObjectId(str(obs["server_id"]))})
                if srv:
                    srv["_id"] = str(srv["_id"])
                    server = srv
    except Exception:
        pass

    first_seen_iso = first_seen_at.isoformat()

    # Re-analysis hygiene: wipe any stale PENDING ai_actions rows from a prior
    # run on this anomaly. Approved/rejected rows stay as audit trail; only
    # the still-pending ones (which the operator hadn't yet acted on) get
    # superseded by whatever the new run produces.
    try:
        deleted = await clear_pending_actions_for_source("anomaly", observation_id)
        if deleted:
            logger.info("[anomaly_triage] cleared %d stale pending ai_actions row(s) for observation %s", deleted, observation_id)
    except Exception as e:
        logger.warning("[anomaly_triage] clear_pending_actions failed for observation %s: %s", observation_id, e)

    tools = bind_tools_for_server(server, run_id, source_type=SourceType.ANOMALY, source_id=observation_id)
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
    # Snapshot of stream_buffer length at the start of each model turn — lets the
    # on_chat_model_end handler detect whether the model actually streamed (token
    # events fired) or just dropped a full response in the end event (non-streaming
    # providers). When the buffer didn't grow during the turn, we harvest content
    # from on_chat_model_end so the analysis isn't silently empty.
    buffer_size_at_turn_start = 0

    _emit_ws(server_id, WSEvent.AI_ANALYSIS_TOKEN, {
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
                    _emit_ws(server_id, WSEvent.AI_ANALYSIS_TOKEN, {
                        "run_id": run_id,
                        "source_type": "anomaly",
                        "source_id": observation_id,
                        "token": token_text,
                    })

            elif etype == "on_chat_model_end":
                turn_count += 1
                # Robustness: some models (or some langchain providers) don't emit
                # on_chat_model_stream chunks at all — they only fire on_chat_model_end
                # with the full message. We detect that by comparing the buffer length
                # to the snapshot taken at the start of this turn; if it didn't grow,
                # we harvest the full content from the end event and push it as one
                # synthetic token so the frontend sees it.
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
                streamed_this_turn = len(stream_buffer) > buffer_size_at_turn_start
                if output_content and not streamed_this_turn:
                    _emit_ws(server_id, WSEvent.AI_ANALYSIS_TOKEN, {
                        "run_id": run_id,
                        "source_type": "anomaly",
                        "source_id": observation_id,
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
                        "source_type": "anomaly",
                        "source_id": observation_id,
                        "token": separator,
                    })
                # Snapshot AFTER separator so the next turn's streamed-this-turn
                # check doesn't falsely count the separator as model output.
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
        logger.error("[anomaly_triage] agent error for %s: %s: %s", observation_id, type(e).__name__, e)
        traceback.print_exc()

    # Fallback: if on_chain_end never delivered messages, reconstruct from the stream buffer
    if not final_messages and stream_buffer:
        from langchain_core.messages import AIMessage
        final_messages = [AIMessage(content="".join(stream_buffer))]

    logger.debug("[anomaly_triage] %s captured: final_messages=%d stream_buffer_chars=%d", observation_id, len(final_messages), sum(len(s) for s in stream_buffer))

    elapsed = time.monotonic() - t0
    logger.info("[ai_anomaly] observation=%s run=%s elapsed=%.2fs turns=%s", observation_id, run_id, elapsed, turn_count)

    # If the agent produced nothing at all — no messages AND no streamed tokens
    # — surface the failure to the caller so the router returns 503 instead of
    # silently saving an empty analysis row.
    if not final_messages and not stream_buffer:
        _emit_ws(server_id, WSEvent.AI_ANALYSIS_COMPLETE, {
            "run_id": run_id,
            "source_type": "anomaly",
            "source_id": observation_id,
            "analysis_id": None,
            "error": "agent_produced_no_output",
        })
        await notify(
            type=NotificationType.AI_ANALYSIS_FAILED,
            category=NotificationCategory.AI,
            severity=NotificationSeverity.ERROR,
            title="Anomaly analysis failed",
            body="The AI agent produced no output. Please try running the analysis again.",
            link=f"/anomalies/{observation_id}",
            server_id=server_id,
            entity_type="anomaly",
            entity_id=observation_id,
        )
        raise RuntimeError(
            f"Anomaly triage agent produced no output for observation {observation_id} "
            f"(run {run_id}, elapsed {elapsed:.2f}s). Check the [anomaly_triage] log lines above "
            f"for the underlying exception."
        )

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

    # Prefer the full streamed buffer for saving — it contains EVERY token
    # the model emitted, including analysis sections produced in the same
    # AIMessage as a tool call. `_extract_final_text` drops those because it
    # skips messages with tool_calls. The buffer matches what the user saw
    # streaming on-screen.
    use_buffer_as_source = bool(full_stream) and "need more steps" not in full_stream.lower()[:80]

    # Choose display text — see note above the use_buffer_as_source flag
    if use_buffer_as_source:
        raw_text = full_stream
    elif raw_text_messages:
        raw_text = raw_text_messages
    else:
        raw_text = ""

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
    # Phase 28.5 — separate from `suggested_commands` (which are auto-executable
    # shell commands). `library_suggestions` holds proposals for creating new
    # server-scoped rules from the anomaly pattern.
    library_suggestions = parsed.get("suggestions") or []

    logger.debug(
        "[anomaly_triage] %s: json_found=%s suggestions=%d manual=%d msg_chars=%d stream_chars=%d",
        observation_id, bool(parsed), len(suggestions), len(manual_commands),
        len(raw_text_messages), len(full_stream),
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
        analysis_type=AnalysisType.ANOMALY_TRIAGE,
        source_type=SourceType.ANOMALY,
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
        source_type=SourceType.ANOMALY,
        source_id=observation_id,
        server_id=server_id,
        suggestions=suggestions,
    )

    if command_ids:
        await db[Collections.AI_ANALYSIS].update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": {"structured.suggested_command_ids": command_ids}},
        )

    # Phase 28.5 — queue any per-server library suggestions (create_server_rule)
    # the LLM emitted. Skipped on read_only-mode servers.
    autonomy = server.get("ai_autonomy_level", "read_only")
    if autonomy == "suggest" and library_suggestions:
        try:
            await _queue_anomaly_library_suggestions(
                suggestions=library_suggestions,
                run_id=run_id,
                analysis_id=analysis_id,
                observation_id=observation_id,
                server_id=str(server_id),
            )
        except Exception as e:
            logger.warning("[anomaly_triage] queue library suggestions failed: %s: %s", type(e).__name__, e)

    # Emit completion signal
    _emit_ws(server_id, WSEvent.AI_ANALYSIS_COMPLETE, {
        "run_id": run_id,
        "source_type": "anomaly",
        "source_id": observation_id,
        "analysis_id": analysis_id,
    })

    await notify(
        type=NotificationType.AI_ANALYSIS_READY,
        category=NotificationCategory.AI,
        severity=NotificationSeverity.SUCCESS,
        title="Anomaly analysis ready",
        body=(summary or "AI analysis complete.")[:160],
        link=f"/anomalies/{observation_id}",
        server_id=server_id,
        entity_type="anomaly",
        entity_id=observation_id,
    )

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


async def _queue_anomaly_library_suggestions(
    *,
    suggestions: list,
    run_id: str,
    analysis_id: str,
    observation_id: str,
    server_id: str,
) -> list[str]:
    """
    Phase 28.5 — queue `create_server_rule` proposals emitted by anomaly
    triage. Anomalies are by definition uncovered-by-rule patterns, so they're
    the most natural surface for promoting a recurring fingerprint into a
    first-class server-scoped rule.

    Other action types (`create_server_script`, `swap_remediation_script`)
    are intentionally NOT supported here — anomalies haven't fired any
    remediation, so there's nothing to swap or attach a script to.
    """
    if not suggestions:
        return []
    from app.core.database import get_database
    db = get_database()
    now = utc_now()
    inserted: list[str] = []

    for sug in suggestions:
        if not isinstance(sug, dict) or sug.get("action") != "create_server_rule":
            continue
        payload = {
            "server_id": server_id,
            "name": str(sug.get("name", ""))[:200],
            "pattern": str(sug.get("pattern", ""))[:2000],
            "severity": sug.get("severity") if sug.get("severity") in ("low", "medium", "high", "critical") else "medium",
            "action_level": int(sug.get("action_level") or 3),
            "description": str(sug.get("description", ""))[:1000],
            "os_type": sug.get("os_type") if sug.get("os_type") in ("linux", "windows", "common") else "common",
            "tags": [str(t)[:50] for t in (sug.get("tags") or [])][:10],
            "remediation_script_id": sug.get("remediation_script_id") or None,
            "reason": (sug.get("reason") or "")[:500],
            "ai_analysis_id": analysis_id,
        }
        row = {
            "action_type": "create_server_rule",
            "payload": payload,
            "run_id": run_id,
            "source_type": "anomaly",
            "source_id": observation_id,
            "server_id": server_id,
            "status": "pending",
            "created_at": now,
            "decided_at": None,
            "decided_by": None,
        }
        result = await db[Collections.AI_ACTIONS].insert_one(row)
        inserted.append(str(result.inserted_id))

    if inserted:
        try:
            event_bus.emit(WSTopic.AI_ACTIONS, "action.created", {
                "server_id": server_id,
                "count": len(inserted),
                "source": "anomaly_triage",
            })
        except Exception:
            pass
        await notify(
            type=NotificationType.AI_SUGGESTIONS_QUEUED,
            category=NotificationCategory.AI,
            severity=NotificationSeverity.INFO,
            title="AI suggestions ready for review",
            body=f"{len(inserted)} suggested action(s) from anomaly triage await your approval.",
            link="/ai-actions",
            server_id=server_id,
            entity_type="ai_actions",
            entity_id=run_id,
        )
    return inserted
