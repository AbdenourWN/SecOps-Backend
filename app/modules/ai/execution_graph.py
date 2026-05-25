"""
AI command execution graph.

Entry point: run_execution_batch(batch_id, command_ids)

For each approved command in sequence:
  1. Check guardrails (block list / rate limit)
  2. Pull source-alert + triage analysis context (`_fetch_impact_context`)
  3. Capture pre_snapshot (metrics window, server state) anchored at "now"
  4. Server-online guard, then execute via terminal_pool
  5. ~4s settling delay so post-exec logs/metrics can land
  6. Capture post_snapshot anchored at "now"
  7. Fetch impact logs (10 lines at source-alert time + 10 latest, deduped by ES _id)
  8. Run impact agent with full context → save to ai_analysis (analysis_type="command_impact")
  9. Denormalize verdict + summary + addressed_root_cause onto ai_command row
"""
import asyncio
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from bson import ObjectId
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.events import event_bus
from app.modules.servers.guardrails import check_command
from app.modules.ai.llm import get_chat_model
from app.modules.ai.analysis_store import save_analysis, get_analysis_by_id
from app.modules.ai.tools_read import ALL_READ_TOOLS
from app.modules.ai.snapshots import capture_snapshot, fetch_review_logs


IMPACT_SYSTEM_PROMPT = """You are a SOC analyst reviewing the result of a remediation command that was just executed on a server. Your job is to decide whether the command **addressed the diagnosed root cause** of the original alert — not just whether anything changed.

## What you receive

1. **Source alert** — the incident or anomaly that triggered the command (severity, rule name / reasons, when it fired, the matched log line).
2. **Triage diagnosis** — the prior AI analysis: summary, root cause hypothesis, confidence. Treat this as "what we believed was wrong."
3. **Command details** — the command text, its stated purpose, expected outcome, and risk level.
4. **Execution result** — exit code, stdout, stderr.
5. **Pre-snapshot metrics** — metric time series for the ~5 minutes leading up to execution.
6. **Post-snapshot metrics** — metric time series for the ~5 minutes after execution (captured after a ~4 s settling delay).
7. **Logs evidence — two slices, deduplicated by document ID, no overlap:**
   - **Logs at the source alert time** — ~10 log lines bracketing the moment the alert originally fired (5 immediately before + 5 immediately after).
   - **Most recent logs** — the 10 newest log lines on the server right now.
   Use the first slice to ground "what the problem looked like" and the second to ground "what the system looks like after the command." If the recent slice no longer contains the diagnostic patterns from the source slice, that's strong evidence of improvement.

## What you must produce

Write a short Markdown analysis (3-6 sentences). Reference **specific timestamps, metric numbers, and log fragments** as evidence — do not write generic phrases like "the command worked."

Then end with a ```json block in this exact shape:

```json
{
  "outcome": "resolved|partial|no_effect|made_worse",
  "addressed_root_cause": "yes|partial|no|unknown",
  "before_after_delta": "1-2 line factual diff (e.g. CPU 92% → 14%, sshd auth failures stopped)",
  "evidence": [
    "CPU dropped from 92% at 10:14:02 to 14% at 10:14:08",
    "sshd 'authentication failure' lines absent from the most recent log slice"
  ],
  "follow_up_required": false,
  "follow_up_reason": null,
  "next_recommended_action": null
}
```

**Field definitions:**

- `outcome`:
  - `resolved` — metrics/logs confirm the issue is fixed
  - `partial` — improvement but issue persists
  - `no_effect` — command ran successfully but nothing measurable changed
  - `made_worse` — metrics or logs indicate degradation after execution
- `addressed_root_cause`:
  - `yes` — the command directly targeted what triage diagnosed and the data shows it worked
  - `partial` — addressed part of the diagnosis but not all
  - `no` — command ran but did not address the diagnosed root cause (e.g. it cleared a symptom but the cause remains)
  - `unknown` — insufficient evidence in the data to judge
- `evidence` — a list of **concrete factual statements** drawn from the metrics/logs sections, each citing a number or log fragment. Aim for 2-4 items. Empty list is allowed only when there is genuinely no evidence (e.g. command produced no output and metrics are flat).
- `follow_up_required` / `follow_up_reason` / `next_recommended_action` — populate if `outcome` is `partial`, `no_effect`, or `made_worse`. Otherwise `false` / `null` / `null`.

Use read tools only if you genuinely need additional context beyond what's provided — most assessments should be possible from the pre-fetched data alone.
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


async def _fetch_impact_context(cmd_doc: dict) -> dict:
    """
    Pull the source incident/anomaly + the original triage analysis so the
    impact agent knows WHAT problem the command was meant to fix.

    Returns:
      source_type, source_id, source_doc, source_anchor (datetime|None),
      rule_name, triage_summary, triage_markdown, triage_structured,
      triage_confidence
    """
    db = get_database()
    src_type = cmd_doc.get("source_type", "")
    src_id = cmd_doc.get("source_id", "")
    analysis_id_triage = cmd_doc.get("analysis_id", "")

    source_doc: dict = {}
    rule_name = ""
    if src_id:
        try:
            oid = ObjectId(src_id)
            if src_type == "incident":
                source_doc = await db["incidents"].find_one({"_id": oid}) or {}
                if source_doc.get("rule_id"):
                    rule = await db["rules"].find_one(
                        {"_id": ObjectId(str(source_doc["rule_id"]))}, {"name": 1}
                    )
                    rule_name = (rule or {}).get("name", "")
            elif src_type == "anomaly":
                source_doc = await db["log_observations"].find_one({"_id": oid}) or {}
        except Exception:
            source_doc = {}

    triage: dict = {}
    if analysis_id_triage:
        try:
            triage = await get_analysis_by_id(analysis_id_triage) or {}
        except Exception:
            triage = {}

    source_anchor: Optional[datetime] = None
    if src_type == "incident":
        source_anchor = source_doc.get("detected_at")
    elif src_type == "anomaly":
        source_anchor = source_doc.get("first_seen_at") or source_doc.get("last_seen_at")
    if isinstance(source_anchor, datetime) and source_anchor.tzinfo is None:
        source_anchor = source_anchor.replace(tzinfo=timezone.utc)
    if not isinstance(source_anchor, datetime):
        source_anchor = None

    return {
        "source_type": src_type,
        "source_id": src_id,
        "source_doc": source_doc,
        "source_anchor": source_anchor,
        "rule_name": rule_name,
        "triage_summary": triage.get("summary", ""),
        "triage_markdown": triage.get("markdown", ""),
        "triage_structured": triage.get("structured", {}) or {},
        "triage_confidence": triage.get("confidence", 0.0),
    }


def _emit_progress(server_id: str, command_id: str, phase: str, **kwargs):
    payload = {"command_id": command_id, "server_id": server_id, "phase": phase, **kwargs}
    try:
        event_bus.emit(f"servers.{server_id}.ai", "ai_command_progress", payload)
    except Exception:
        pass
    try:
        event_bus.emit("ai_actions", "ai_command_progress", payload)
    except Exception:
        pass


def _fmt_metrics_table(points: list) -> str:
    if not points:
        return "_No metric points in window._"
    rows = ["| Timestamp | CPU % | RAM % | Disk % |", "|---|---|---|---|"]
    for p in points:
        rows.append(
            f"| {p.get('t', '')} | "
            f"{p.get('cpu') if p.get('cpu') is not None else '—'} | "
            f"{p.get('ram') if p.get('ram') is not None else '—'} | "
            f"{p.get('disk') if p.get('disk') is not None else '—'} |"
        )
    return "\n".join(rows)


def _fmt_log_lines(logs: list) -> str:
    if not logs:
        return "_No log lines._"
    lines = [f"[{l.get('t', '')}] [{(l.get('level') or '').upper():7}] {l.get('msg', '')}" for l in logs]
    return "```\n" + "\n".join(lines) + "\n```"


def _build_impact_user_message(
    *,
    command: str,
    purpose: str,
    expected_outcome: str,
    risk_level: str,
    stdout: str,
    stderr: str,
    exit_code: Optional[int],
    pre_snapshot: dict,
    post_snapshot: dict,
    impact_context: dict,
    impact_logs: dict,
    server_id: str,
    command_id: str,
) -> str:
    src_doc = impact_context.get("source_doc") or {}
    src_type = impact_context.get("source_type", "")
    rule_name = impact_context.get("rule_name", "")
    triage_summary = impact_context.get("triage_summary", "")
    triage_structured = impact_context.get("triage_structured") or {}
    triage_md = (impact_context.get("triage_markdown") or "")[:1500]

    if src_type == "incident":
        source_block = (
            f"- **Type**: incident\n"
            f"- **Severity**: {src_doc.get('severity', '?')}\n"
            f"- **Rule**: {rule_name or src_doc.get('rule_id', '?')}\n"
            f"- **Detected at**: {src_doc.get('detected_at', '?')}\n"
            f"- **Status**: {src_doc.get('status', '?')}\n"
            f"- **Description**: {src_doc.get('description', '?')}\n"
        )
    elif src_type == "anomaly":
        reasons = ", ".join(src_doc.get("reasons", [])) or "n/a"
        source_block = (
            f"- **Type**: anomaly\n"
            f"- **Severity**: {src_doc.get('severity', '?')}\n"
            f"- **Score**: {src_doc.get('score', '?')}\n"
            f"- **Reasons**: {reasons}\n"
            f"- **Occurrences**: {src_doc.get('occurrence_count', 1)}\n"
            f"- **First seen**: {src_doc.get('first_seen_at', '?')}\n"
            f"- **Last seen**: {src_doc.get('last_seen_at', '?')}\n"
            f"- **Sample log**: {(src_doc.get('log_message') or 'n/a')[:300]}\n"
        )
    else:
        source_block = "_No source alert context available._"

    triage_block = (
        f"- **Summary**: {triage_summary or '—'}\n"
        f"- **Root cause hypothesis**: {triage_structured.get('root_cause_hypothesis', '—')}\n"
        f"- **Confidence**: {triage_structured.get('confidence', '—')}\n"
        f"- **Severity assessment**: {triage_structured.get('severity_assessment', '—')}\n"
        f"- **Impact at time of triage**: {triage_structured.get('impact_now', '—')}\n\n"
        f"_Triage narrative (truncated to 1500 chars):_\n\n{triage_md if triage_md else '_no markdown available_'}"
    )

    pre_metrics = pre_snapshot.get("metrics_window") or []
    post_metrics = post_snapshot.get("metrics_window") or []
    pre_state = pre_snapshot.get("server_state") or {}
    post_state = post_snapshot.get("server_state") or {}

    at_source = (impact_logs or {}).get("at_source") or []
    latest = (impact_logs or {}).get("latest") or []

    return (
        f"# Impact assessment request\n\n"
        f"A command was just executed on server `{server_id}` (command id `{command_id}`).\n\n"
        f"## 1. Source alert\n{source_block}\n"
        f"## 2. Triage diagnosis\n{triage_block}\n\n"
        f"## 3. Command details\n"
        f"- **Command**: `{command}`\n"
        f"- **Purpose**: {purpose}\n"
        f"- **Expected outcome**: {expected_outcome}\n"
        f"- **Risk level**: {risk_level}\n\n"
        f"## 4. Execution result\n"
        f"- **Exit code**: {exit_code}\n"
        f"- **stdout** (truncated 2000 chars):\n```\n{(stdout or '')[:2000]}\n```\n"
        f"- **stderr** (truncated 500 chars):\n```\n{(stderr or '')[:500]}\n```\n\n"
        f"## 5. Pre-snapshot metrics (anchor: {pre_snapshot.get('anchor', '?')})\n"
        f"- **Server**: {pre_state.get('hostname', '?')} · online={pre_state.get('is_online', '?')} · status={pre_state.get('status', '?')}\n\n"
        f"{_fmt_metrics_table(pre_metrics)}\n\n"
        f"## 6. Post-snapshot metrics (anchor: {post_snapshot.get('anchor', '?')}, after ~4s settling delay)\n"
        f"- **Server**: {post_state.get('hostname', '?')} · online={post_state.get('is_online', '?')} · status={post_state.get('status', '?')}\n\n"
        f"{_fmt_metrics_table(post_metrics)}\n\n"
        f"## 7. Logs evidence (deduplicated by ES `_id` — no entry appears in both slices)\n\n"
        f"### 7a. Logs at the source alert time (up to 10: 5 before + 5 after the alert anchor)\n"
        f"{_fmt_log_lines(at_source)}\n\n"
        f"### 7b. Most recent logs on the server (up to 10, latest first)\n"
        f"{_fmt_log_lines(list(reversed(latest)))}\n\n"
        f"---\n\n"
        f"Now produce the impact assessment. End with the ```json block exactly as specified in your system prompt."
    )


async def _run_impact_agent(
    *,
    command: str,
    purpose: str,
    expected_outcome: str,
    risk_level: str,
    stdout: str,
    stderr: str,
    exit_code: Optional[int],
    pre_snapshot: dict,
    post_snapshot: dict,
    impact_context: dict,
    impact_logs: dict,
    server_id: str,
    command_id: str,
    run_id: str,
) -> dict:
    """Run the impact analysis LLM for one command. Returns analysis_id + parsed verdict."""
    model = get_chat_model()
    agent = create_react_agent(model=model, tools=list(ALL_READ_TOOLS), prompt=IMPACT_SYSTEM_PROMPT)

    user_message = _build_impact_user_message(
        command=command,
        purpose=purpose,
        expected_outcome=expected_outcome,
        risk_level=risk_level,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        pre_snapshot=pre_snapshot,
        post_snapshot=post_snapshot,
        impact_context=impact_context,
        impact_logs=impact_logs,
        server_id=server_id,
        command_id=command_id,
    )

    result = await agent.ainvoke({"messages": [HumanMessage(content=user_message)]})

    messages = result.get("messages", [])
    raw_text = _extract_final_text(messages)
    parsed = _extract_json_block(raw_text) or {}

    outcome = parsed.get("outcome", "no_effect")
    addressed = parsed.get("addressed_root_cause", "unknown")
    before_after_delta = parsed.get("before_after_delta", "") or ""
    evidence = parsed.get("evidence", []) or []
    markdown = f"## AI Impact Analysis\n\n{raw_text}\n\n---\n*Command: {command_id}*"

    from app.core.config import settings
    analysis_id = await save_analysis(
        run_id=run_id,
        analysis_type="command_impact",
        source_type="command",
        source_id=command_id,
        server_id=server_id,
        summary=before_after_delta or outcome,
        markdown=markdown,
        confidence=0.0,
        structured={
            "outcome": outcome,
            "addressed_root_cause": addressed,
            "before_after_delta": before_after_delta,
            "evidence": evidence,
            "follow_up_required": parsed.get("follow_up_required", False),
            "follow_up_reason": parsed.get("follow_up_reason"),
            "next_recommended_action": parsed.get("next_recommended_action"),
        },
        anchored_at=datetime.now(timezone.utc),
        window_minutes=0,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.LLM_MODEL,
    )

    return {
        "analysis_id": analysis_id,
        "outcome": outcome,
        "addressed_root_cause": addressed,
        "before_after_delta": before_after_delta,
    }


async def run_execution_batch(batch_id: str, command_ids: list[str]) -> dict:
    """
    Run all approved commands in a batch sequentially.
    Each command goes through: guardrails → pre_snapshot → execute → post_snapshot → impact agent.
    Returns summary of what happened.
    """
    db = get_database()
    results = []

    for command_id in command_ids:
        try:
            cmd_doc = await db["ai_command"].find_one({"_id": ObjectId(command_id)})
        except Exception:
            continue
        if not cmd_doc or cmd_doc.get("status") != "approved":
            continue

        command = cmd_doc.get("command", "")
        os_type = cmd_doc.get("os_type", "linux")
        server_id = cmd_doc.get("server_id", "")
        purpose = cmd_doc.get("purpose", "")
        expected_outcome = cmd_doc.get("expected_outcome", "")
        risk_level = cmd_doc.get("risk_level", "medium")
        run_id = cmd_doc.get("run_id", str(uuid.uuid4())[:8])

        # Pull source alert + triage analysis once — used to build the impact prompt
        # and to anchor the source-time log slice for fetch_review_logs.
        impact_context = await _fetch_impact_context(cmd_doc)

        # Guardrails check
        guard = check_command(command, os_type)
        if not guard.allowed:
            await db["ai_command"].update_one(
                {"_id": ObjectId(command_id)},
                {"$set": {
                    "status": "blocked",
                    "blocked_by_guardrail": "block_list",
                    "error": guard.reason or "Blocked by guardrail",
                }},
            )
            _emit_progress(server_id, command_id, "blocked", reason=guard.reason)
            results.append({"command_id": command_id, "status": "blocked"})
            continue

        # Mark executing + emit
        await db["ai_command"].update_one(
            {"_id": ObjectId(command_id)},
            {"$set": {"status": "executing"}},
        )
        _emit_progress(server_id, command_id, "pre_snapshot")

        # Pre-snapshot — anchor at "now" just before execution starts
        pre_anchor = utc_now()
        pre_snapshot = await capture_snapshot(server_id, anchor=pre_anchor)
        await db["ai_command"].update_one(
            {"_id": ObjectId(command_id)},
            {"$set": {"pre_snapshot": pre_snapshot}},
        )

        # Execute
        stdout: str = ""
        stderr: str = ""
        exit_code = None
        duration_ms = None
        exec_error = None
        executed_at = utc_now()

        # ── Server online check before attempting connection ──────────────────
        try:
            srv_doc = await db["servers"].find_one(
                {"_id": ObjectId(server_id)},
                {"is_online": 1, "status": 1, "hostname": 1},
            )
        except Exception:
            srv_doc = None

        if not srv_doc or not srv_doc.get("is_online"):
            srv_status = srv_doc.get("status", "unreachable") if srv_doc else "not found"
            srv_label = srv_doc.get("hostname") or server_id if srv_doc else server_id
            exec_error = f"Server '{srv_label}' is {srv_status} — execution skipped"
            stderr = exec_error
            await db["ai_command"].update_one(
                {"_id": ObjectId(command_id)},
                {"$set": {
                    "status": "failed",
                    "blocked_by_guardrail": "server_offline",
                    "stdout": "",
                    "stderr": stderr,
                    "exit_code": None,
                    "duration_ms": None,
                    "executed_at": executed_at,
                    "error": exec_error,
                }},
            )
            _emit_progress(server_id, command_id, "failed", reason=exec_error)
            results.append({"command_id": command_id, "status": "failed"})
            continue

        try:
            from app.core.connection_pool import terminal_pool
            import time
            async with terminal_pool.get(server_id) as executor:
                t_start = time.monotonic()
                exec_result = await executor.run_command(command, timeout_s=60)
            duration_ms = int((time.monotonic() - t_start) * 1000)

            # executor.run_command returns {status, output, error}
            # "output" = stdout, "error" = stderr/error message
            # "success"           → exit_code 0   → treat as completed
            # "error"             → exit_code != 0 → command ran (non-zero exit is still intel)
            # "timeout"/"aborted"/"failed" → execution problem → mark failed
            exec_status = exec_result.get("status", "failed")
            stdout = (exec_result.get("output") or exec_result.get("stdout") or "").strip()
            stderr = (exec_result.get("error") or exec_result.get("stderr") or "").strip()

            if exec_status == "success":
                status = "completed"
                exit_code = 0
            elif exec_status in ("error", "failed"):
                # If we got any response (stdout or stderr), the command reached
                # the server — that's "completed" with a non-zero exit.
                # Only treat as execution-failed if we got nothing at all.
                if stdout or stderr:
                    status = "completed"
                    exit_code = 1
                else:
                    status = "failed"
                    exit_code = None
                    exec_error = f"Execution ended with status: {exec_status}"
                    stderr = exec_error
            else:
                # timeout, aborted — execution-level problem, command may not have run
                status = "failed"
                exit_code = None
                exec_error = stderr or f"Execution ended with status: {exec_status}"
                if not stderr:
                    stderr = exec_error
        except Exception as e:
            exec_error = str(e)
            stderr = exec_error
            status = "failed"

        # Cap stdout/stderr; ensure stderr always has context when empty
        stdout = stdout[:8000]
        stderr = stderr[:2000]
        if not stdout and not stderr and status == "failed":
            stderr = "(no output captured — command may not have reached the server)"

        await db["ai_command"].update_one(
            {"_id": ObjectId(command_id)},
            {"$set": {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "executed_at": executed_at,
                "status": status,
                "error": exec_error,
            }},
        )
        _emit_progress(server_id, command_id, "executed", exit_code=exit_code, status=status)

        # Settling delay — give the server ~4 s to emit follow-up logs (service
        # restart messages, etc.) and let a fresh metric sample push to ES.
        # Skip when the command never reached the server.
        will_run_impact = status == "completed" or (status == "failed" and (stdout or stderr))
        if will_run_impact:
            await asyncio.sleep(4)

        # Post-snapshot — anchor at "now" after the settling delay
        post_anchor = utc_now()
        post_snapshot = await capture_snapshot(server_id, anchor=post_anchor)
        await db["ai_command"].update_one(
            {"_id": ObjectId(command_id)},
            {"$set": {"post_snapshot": post_snapshot}},
        )

        # Impact agent — skip if the command never reached the server
        if will_run_impact:
            try:
                # Logs slice anchored at the source alert's creation time +
                # 10 most recent server logs (deduplicated by ES _id).
                source_anchor = impact_context.get("source_anchor") or (executed_at - timedelta(minutes=5))
                impact_logs = await fetch_review_logs(server_id, source_anchor=source_anchor)

                impact = await _run_impact_agent(
                    command=command,
                    purpose=purpose,
                    expected_outcome=expected_outcome,
                    risk_level=risk_level,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    pre_snapshot=pre_snapshot,
                    post_snapshot=post_snapshot,
                    impact_context=impact_context,
                    impact_logs=impact_logs,
                    server_id=server_id,
                    command_id=command_id,
                    run_id=run_id,
                )
                await db["ai_command"].update_one(
                    {"_id": ObjectId(command_id)},
                    {"$set": {
                        "impact_analysis_id": impact["analysis_id"],
                        "impact_verdict": impact["outcome"],
                        "impact_addressed_root_cause": impact.get("addressed_root_cause", "unknown"),
                        "impact_summary": (impact["before_after_delta"] or "")[:200],
                    }},
                )
                _emit_progress(server_id, command_id, "report_ready", verdict=impact["outcome"])
            except Exception as e:
                _emit_progress(server_id, command_id, "report_error", error=str(e))

        results.append({"command_id": command_id, "status": status})

    return {"batch_id": batch_id, "results": results}
