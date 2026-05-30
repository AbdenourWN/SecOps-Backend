"""
Server-overview agent — LangGraph ReAct agent for a whole-server analysis.

Entry point: run_server_overview(server_id, hours) -> dict

Differences from triage_graph:
  - Anchors on `now` (not an incident `detected_at`)
  - Pre-fetches a backward window via `build_server_context`
  - No mutation tools; the output is **manual commands only**
  - Writes analysis_type="server_overview", source_type="server"
  - Does NOT call `create_commands()` — manual commands live in `structured.manual_commands`

The output JSON shape (last ```json``` block in the model output):
  {
    "manual_commands": [
      {
        "command": "...",
        "purpose": "...",
        "expected_output": "...",
        "steps": ["...", "..."],
        "risk_level": "low" | "medium" | "high",
        "os_type": "linux" | "windows"
      }
    ],
    "summary_one_line": "...",
    "confidence": 0.0-1.0
  }
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
from app.core.config import settings
from app.modules.ai.llm import get_chat_model
from app.modules.ai.analysis_store import save_analysis
from app.modules.ai.context_builder import build_server_context
from app.modules.ai.tools_read import ALL_READ_TOOLS


SERVER_OVERVIEW_SYSTEM_PROMPT = """You are a Senior Site Reliability + Security Operations engineer producing a holistic health & risk overview for a single server. Your output is for the on-call operator who has just opened the AI Overview tab for that server and wants to know: what's been happening, is anything degrading, is anything suspicious, and what should I check or do next.

## Working Style (read first)

- **Quote logs and metrics verbatim** when you cite a specific number, line, or timestamp — copy them from the pre-fetched context. Reasoned inferences and predictions ARE welcome (that's the point of this analysis) — just don't fabricate concrete specifics (an IP that isn't there, a username you didn't see).
- **Be honest about uncertainty.** If the evidence is thin in a window, say so. A confident "no signal" is more useful than invented urgency.
- **Predict, don't just describe.** This analysis is forward-looking — operators want to know what's about to break, not just what already broke. Use trends in the metric time-series and the rate of incidents/anomalies to project the near future.
- **Always produce manual diagnostic commands.** Even if the server looks fine, give the operator a small set of "if you want to verify, run these" commands. When the server is offline/reachable/has an `auth_failure_reason`, the commands should match the diagnostic guide the operator needs.
- **Write tight, scannable bullets.** Every bullet is one fact, one prediction, or one action.
- **No padding.** Every bullet must add a new fact, prediction, or action. Do not restate what an earlier bullet already said, and do not pad a section with restated context just to fill space. If a section genuinely has nothing to report ("nothing suspicious in window", "no failed remediations"), say that in one line and move on — short is correct when the evidence is thin.

## You Already Have Rich Context

The user message includes a pre-fetched whole-server snapshot for the chosen window (1h / 6h / 24h):
- **Server Profile** — hostname, OS, current status (online / reachable / offline), `auth_failure_reason` if reachable, business hours, autonomy level
- **Metric Time-Series** — CPU/RAM/disk samples across the window
- **Logs** — up to 200 lines in the window
- **Incidents in Window** — every rule fire
- **Anomalies in Window** — Tier-2 observations
- **Remediation Runs in Window** — every `automation_logs` entry with script name + status

Use this context as your primary evidence. Tools are available for drill-down (`get_logs_around`, `get_metrics_around`, `get_pattern_history`, etc.) — call them only when you need a specific extra fact. Most overviews need 0–3 tool calls.

## Required Sections (Markdown, in this order)

Use bullet points (`-`) in every section. No long paragraphs.

### Server State
- Current status (online / reachable / offline) and what that means right now
- If reachable: quote the `auth_failure_reason` verbatim and note this is the headline concern
- If offline: note last successful health check time
- Any status flips during the window

### Resource Trends
- CPU / RAM / disk trajectory across the window (low → high, stable, spiky)
- Call out saturation thresholds: any metric > 85% sustained, or growth rate that projects past 90% within 24h
- Compare against the cached `last_metrics` snapshot

### Suspicious Activity
- Anomalies that fired (severity, score, reasons)
- Off-hours activity (vs business hours)
- Repeating log patterns that look like reconnaissance, brute-force, or scanning
- If nothing suspicious, say so explicitly — don't manufacture concerns

### Recent Incidents & Remediation
- One short bullet per incident in the window: rule name, severity, status, what triggered it
- For each remediation run: did it succeed? Did the underlying incident return?
- Flag any remediation that failed multiple times — those need escalation

### Risks & Predictions
- Concrete forward-looking concerns based on the trends above. Examples:
  - "Disk at 78% growing ~2%/h → likely to hit 90% in ~6h at current rate"
  - "Remediation X has failed 3× consecutively — automation is exhausted, manual intervention needed"
  - "Repeated SSH auth failures from 203.0.113.7 over the last 4h — brute-force in progress"
- If no real risks, say "No elevated risk in window" — don't fabricate.

### Manual Diagnostic Commands

Write a final ```json``` block with this exact shape:

```json
{
  "manual_commands": [
    {
      "command": "Get-Service WinRM",
      "purpose": "Verify the WinRM service is running on the VM",
      "expected_output": "Status : Running",
      "steps": [
        "Open an Administrator PowerShell on the VM (RDP if needed)",
        "Run the command verbatim",
        "If Status is anything other than Running, run: Start-Service WinRM"
      ],
      "risk_level": "low",
      "os_type": "windows"
    }
  ],
  "summary_one_line": "Server reachable but WinRM auth probe rejected — run the diagnostic checklist to confirm policy vs credential vs service state.",
  "confidence": 0.75,
  "suggestions": []
}
```

### `suggestions` array (only on `suggest`-mode servers)

If the prompt context says the server's `ai_autonomy_level` is `suggest`,
you MAY populate `suggestions[]` with concrete per-server library actions
when the whole-window evidence strongly justifies them. Otherwise leave it
empty `[]`. Each suggestion will be queued as a separate `ai_actions` row
for operator approval; approval auto-flips the server's library mode from
`global` to `both` so the new entry actually fires.

```json
{
  "action": "create_server_rule",
  "reason": "Reconnaissance pattern fires 8x/h on this server but no global rule covers it. Cite specific log lines.",
  "name": "<rule name>",
  "pattern": "<Python regex>",
  "severity": "low|medium|high|critical",
  "action_level": 1|2|3,
  "description": "<short description>",
  "os_type": "linux|windows|common",
  "tags": ["recon"]
}
{
  "action": "create_server_rule_with_script",
  "reason": "Recurring incident on this server has no rule AND no remediation; here's a detection plus a safe responder, linked.",
  "rule_name": "<rule name>",
  "pattern": "<Python regex>",
  "severity": "low|medium|high|critical",
  "action_level": 1|2|3,
  "rule_description": "<short description>",
  "os_type": "linux|windows|common",
  "tags": ["..."],
  "script_name": "<script name>",
  "script_description": "<short purpose>",
  "language": "bash|powershell|python",
  "content": "<full script body>",
  "target_os": "linux|windows",
  "category": "diagnostic|containment|recovery"
}
{
  "action": "swap_remediation_script",
  "reason": "Global script for rule X has failed 3x on this server — proposed replacement adapted to this server's environment.",
  "rule_id": "<rule id>",
  "language": "bash|powershell|python",
  "target_os": "linux|windows",
  "new_script_content": "<full replacement script — keep the SAME name as the global one>"
}
```

Be conservative — only propose new rules/scripts when the data clearly
shows the global library doesn't cover the case. An empty `suggestions`
array is correct when the overview is normal or when the cause is unclear.
Never propose a standalone script with no rule to fire it — use
`create_server_rule_with_script` so the helper is actually reachable.

Rules for `manual_commands`:
- 3–8 commands is the sweet spot. Each one should test a distinct hypothesis or perform a distinct fix step.
- `command` is the literal shell/PowerShell line the operator will paste.
- `purpose` is one short sentence: what does this prove or fix?
- `expected_output` is a short snippet the operator should look for to know it worked (or what indicates failure).
- `steps` is a 2–4 item ordered checklist that walks the operator through running the command and interpreting the result — including the follow-up command to run if the result is bad.
- `risk_level` is "low" for read-only diagnostics, "medium" for service restarts / config changes, "high" for destructive changes.
- `os_type` matches the server's OS unless the command is OS-agnostic (rare).

DO NOT use ```json``` blocks anywhere else in your response — only at the very end. The frontend extracts the last one.
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


def _emit_ws(server_id: str, event_type: str, payload: dict):
    try:
        event_bus.emit(f"servers.{server_id}.ai", event_type, payload)
    except Exception:
        pass
    try:
        event_bus.emit("ai_actions", event_type, payload)
    except Exception:
        pass


async def run_server_overview(server_id: str, hours: int = 24) -> dict:
    """
    Run the server-overview agent for a single server over the last `hours` hours.
    Returns a dict: analysis_id, run_id, markdown, summary, manual_commands, confidence, analyzed_at.
    Raises RuntimeError if the agent produced no output (caller surfaces 503).
    """
    db = get_database()
    run_id = str(uuid.uuid4())[:8]
    t0 = time.monotonic()
    now = datetime.now(timezone.utc)

    server: dict = {}
    try:
        srv = await db["servers"].find_one({"_id": ObjectId(server_id)})
        if srv:
            srv["_id"] = str(srv["_id"])
            server = srv
    except Exception:
        pass

    # Server overview needs more headroom than triage — 6 evidence sources, up
    # to 24h, plus the manual-commands JSON block at the end. The dedicated env
    # var lets ops tune this independently of the (smaller) triage budget.
    model = get_chat_model(max_tokens_override=settings.LLM_MAX_TOKENS_SERVER_OVERVIEW)
    tools = ALL_READ_TOOLS  # No mutation tools — manual-only output

    # 1. Pre-fetch context
    try:
        ctx_block = await build_server_context(server_id, hours=hours)
    except Exception as e:
        ctx_block = f"_Context pre-fetch failed: {e}_"

    # 2. Build initial user message
    user_message = (
        f"Produce the AI Overview for server **{server.get('hostname', 'unknown')}** "
        f"(server_id={server_id}, os={server.get('os_type', 'linux')}, "
        f"status={server.get('status', 'unknown')}) covering the last **{hours}h**.\n\n"
        f"---\n\n{ctx_block}\n\n---\n\n"
        f"Using this context and any additional tool calls needed, produce the full overview "
        f"following the format in your system prompt. "
        f"End with the ```json block."
    )

    # 3. Stream tokens
    agent = create_react_agent(model=model, tools=tools, prompt=SERVER_OVERVIEW_SYSTEM_PROMPT)
    final_messages: list = []
    turn_count = 0
    stream_buffer: list[str] = []
    buffer_size_at_turn_start = 0

    _emit_ws(server_id, "ai_analysis_token", {
        "run_id": run_id, "source_type": "server", "source_id": server_id, "token": ""
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
                        "source_type": "server",
                        "source_id": server_id,
                        "token": token_text,
                    })

            elif etype == "on_chat_model_end":
                turn_count += 1
                # Robustness: harvest from end event when tokens didn't stream
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
                        _emit_ws(server_id, "ai_analysis_token", {
                            "run_id": run_id,
                            "source_type": "server",
                            "source_id": server_id,
                            "token": output_content,
                        })
                        stream_buffer.append(output_content)
                if stream_buffer and not stream_buffer[-1].endswith("\n\n"):
                    separator = "\n\n"
                    stream_buffer.append(separator)
                    _emit_ws(server_id, "ai_analysis_token", {
                        "run_id": run_id,
                        "source_type": "server",
                        "source_id": server_id,
                        "token": separator,
                    })
                buffer_size_at_turn_start = len(stream_buffer)

            elif etype == "on_chain_end":
                output = ev.get("data", {}).get("output")
                if isinstance(output, dict):
                    msgs = output.get("messages", [])
                    if len(msgs) > len(final_messages):
                        final_messages = msgs

    except Exception as e:
        import traceback
        print(f"[server_overview] agent error for {server_id}: {type(e).__name__}: {e}")
        traceback.print_exc()

    if not final_messages and stream_buffer:
        from langchain_core.messages import AIMessage
        final_messages = [AIMessage(content="".join(stream_buffer))]

    elapsed = time.monotonic() - t0
    print(f"[ai_server_overview] server={server_id} run={run_id} elapsed={elapsed:.2f}s turns={turn_count}")

    # Hard-fail if the agent produced absolutely nothing
    if not final_messages and not stream_buffer:
        _emit_ws(server_id, "ai_analysis_complete", {
            "run_id": run_id,
            "source_type": "server",
            "source_id": server_id,
            "analysis_id": None,
            "error": "agent_produced_no_output",
        })
        raise RuntimeError(
            f"Server-overview agent produced no output for server {server_id} "
            f"(run {run_id}, elapsed {elapsed:.2f}s). Check the [server_overview] log lines above."
        )

    raw_text_messages = _extract_final_text(final_messages)
    full_stream = "".join(stream_buffer)

    if full_stream and "need more steps" not in full_stream.lower()[:80]:
        raw_text = full_stream
    elif raw_text_messages:
        raw_text = raw_text_messages
    else:
        raw_text = ""

    parsed = (
        _extract_json_block(raw_text_messages)
        or _extract_json_block(full_stream)
        or {}
    )

    manual_commands = parsed.get("manual_commands", [])
    summary = parsed.get("summary_one_line", (raw_text[:200] if raw_text else "Server overview complete."))
    confidence = float(parsed.get("confidence", 0.0))
    suggestions = parsed.get("suggestions") or []

    print(
        f"[server_overview] {server_id}: json_found={bool(parsed)} "
        f"manual={len(manual_commands)} msg_chars={len(raw_text_messages)} "
        f"stream_chars={len(full_stream)}"
    )

    structured = {
        "manual_commands": manual_commands,
        "summary_one_line": summary,
        "confidence": confidence,
    }

    markdown = f"## AI Server Overview ({hours}h window)\n\n{raw_text}\n\n---\n*Run ID: {run_id} · Server: {server_id}*"

    analysis_id = await save_analysis(
        run_id=run_id,
        analysis_type="server_overview",
        source_type="server",
        source_id=server_id,
        server_id=server_id,
        summary=summary,
        markdown=markdown,
        confidence=confidence,
        structured=structured,
        anchored_at=now,
        window_minutes=hours * 60,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.LLM_MODEL,
    )

    # Phase 28.5 — queue per-server library suggestions if the server is in
    # `suggest` mode. read_only servers skip this silently.
    autonomy = server.get("ai_autonomy_level", "read_only")
    pending_action_ids: list[str] = []
    if autonomy == "suggest" and suggestions:
        try:
            pending_action_ids = await _queue_overview_suggestions(
                suggestions=suggestions,
                run_id=run_id,
                analysis_id=analysis_id,
                server_id=server_id,
            )
        except Exception as e:
            print(f"[server_overview] queue suggestions failed: {type(e).__name__}: {e}")

    _emit_ws(server_id, "ai_analysis_complete", {
        "run_id": run_id,
        "source_type": "server",
        "source_id": server_id,
        "analysis_id": analysis_id,
        "pending_action_ids": pending_action_ids,
    })

    return {
        "analysis_id": analysis_id,
        "run_id": run_id,
        "markdown": markdown,
        "summary": summary,
        "confidence": confidence,
        "manual_commands": manual_commands,
        "pending_action_ids": pending_action_ids,
        "hours": hours,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


async def _queue_overview_suggestions(
    *,
    suggestions: list,
    run_id: str,
    analysis_id: str,
    server_id: str,
) -> list[str]:
    """
    Phase 28.5 — insert one `ai_actions` row per AI-emitted server-overview
    suggestion. Returns the list of inserted action ids so the frontend can
    light up the new badges immediately.

    Mirrors the shape used by `script_review._queue_suggestion_actions` so
    the approval router branches stay common across surfaces.
    """
    if not suggestions:
        return []
    from app.core.database import get_database
    db = get_database()
    now = utc_now()
    inserted: list[str] = []

    for sug in suggestions:
        if not isinstance(sug, dict):
            continue
        action = sug.get("action")
        reason = (sug.get("reason") or "")[:500]
        if action == "create_server_rule":
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
                "reason": reason,
                "ai_analysis_id": analysis_id,
            }
        elif action == "create_server_script":
            payload = {
                "server_id": server_id,
                "name": str(sug.get("name", ""))[:200],
                "description": str(sug.get("description", ""))[:1000],
                "language": sug.get("language") if sug.get("language") in ("bash", "powershell", "python") else "bash",
                "content": str(sug.get("content", ""))[:20000],
                "target_os": sug.get("target_os") if sug.get("target_os") in ("linux", "windows") else "linux",
                "category": sug.get("category") if sug.get("category") in ("diagnostic", "containment", "recovery") else "recovery",
                "reason": reason,
                "ai_analysis_id": analysis_id,
            }
        elif action == "create_server_rule_with_script":
            payload = {
                "server_id": server_id,
                "rule_name": str(sug.get("rule_name", ""))[:200],
                "pattern": str(sug.get("pattern", ""))[:2000],
                "severity": sug.get("severity") if sug.get("severity") in ("low", "medium", "high", "critical") else "medium",
                "action_level": int(sug.get("action_level") or 3),
                "rule_description": str(sug.get("rule_description", ""))[:1000],
                "os_type": sug.get("os_type") if sug.get("os_type") in ("linux", "windows", "common") else "common",
                "tags": [str(t)[:50] for t in (sug.get("tags") or [])][:10],
                "script_name": str(sug.get("script_name", ""))[:200],
                "script_description": str(sug.get("script_description", ""))[:1000],
                "language": sug.get("language") if sug.get("language") in ("bash", "powershell", "python") else "bash",
                "content": str(sug.get("content", ""))[:20000],
                "target_os": sug.get("target_os") if sug.get("target_os") in ("linux", "windows") else "linux",
                "category": sug.get("category") if sug.get("category") in ("diagnostic", "containment", "recovery") else "recovery",
                "reason": reason,
                "ai_analysis_id": analysis_id,
            }
        elif action == "swap_remediation_script":
            payload = {
                "server_id": server_id,
                "rule_id": sug.get("rule_id") or "",
                "new_script_content": str(sug.get("new_script_content", ""))[:20000],
                "language": sug.get("language") if sug.get("language") in ("bash", "powershell", "python") else "bash",
                "target_os": sug.get("target_os") if sug.get("target_os") in ("linux", "windows") else "linux",
                "reason": reason,
                "ai_analysis_id": analysis_id,
            }
        else:
            continue

        row = {
            "action_type": action,
            "payload": payload,
            "run_id": run_id,
            "source_type": "server",
            "source_id": server_id,
            "server_id": server_id,
            "status": "pending",
            "created_at": now,
            "decided_at": None,
            "decided_by": None,
        }
        result = await db["ai_actions"].insert_one(row)
        inserted.append(str(result.inserted_id))

    if inserted:
        try:
            event_bus.emit("ai_actions", "action.created", {
                "server_id": server_id,
                "count": len(inserted),
                "source": "server_overview",
            })
        except Exception:
            pass
    return inserted
