"""
Automatic post-execution AI review for L1/L2 remediation scripts.

Triggered fire-and-forget from `AutomationService.execute_remediation`.
Reads pre/post snapshots + the script's stdout/stderr and produces a verdict
("did this fix actually address the root cause?") plus, on `suggest`-mode
servers, structured suggestion actions queued into `ai_actions`.

Saves the full review to `ai_analysis` (`analysis_type="script_execution_review"`)
and denormalises verdict + summary back onto the originating `automation_logs`
row so the history list and incident-detail page can render the badge without
a second fetch.
"""
import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from langchain_core.messages import HumanMessage

from app.core.config import settings
from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.events import event_bus
from app.modules.ai.analysis_store import save_analysis
from app.modules.ai.llm import get_chat_model
from app.modules.ai.snapshots import capture_snapshot, fetch_review_logs


# 10s is the right default for scripts (vs 4s for single commands). Scripts can
# restart services, kill processes, rotate firewalls — they take longer to
# settle than a one-line probe.
REMEDIATION_SETTLING_SECONDS = 10


SCRIPT_REVIEW_SYSTEM_PROMPT = """You are a SOC analyst reviewing an automated remediation script that just ran on a server in response to a security/operational incident. Your job is to decide whether the script **actually addressed the root cause** of the incident — not just whether it exited successfully. A script can return exit code 0 and still have done nothing useful (e.g. `Start-Service` returned "Access denied" but the wrapper exited 0 anyway), and a non-zero exit can still represent a genuine improvement if the metrics/logs say so.

## What you receive

1. **The incident** that fired the remediation — rule name, severity, triggering log line, `detected_at`.
2. **The script** — name, language (bash / powershell / python), category (diagnostic / containment / recovery), full content.
3. **Execution outcome** — status (`success` / `failed`), `exit_code` if available, stdout, stderr, executed_at.
4. **Pre-snapshot** — server state + metric window (~5 min) anchored just before the script started.
5. **Post-snapshot** — same shape, anchored ~10s after the script finished (settling window).
6. **Logs evidence — two slices, deduplicated by ES `_id`:**
   - **At source alert time** — ~10 lines bracketing when the incident originally fired.
   - **Most recent** — the 10 newest log lines on the server right now.

## What you produce

A short Markdown analysis (3-6 sentences) citing concrete evidence — metric numbers, log fragments, timestamps. Then end with a ```json block in this exact shape:

```json
{
  "outcome": "resolved|partial|no_effect|made_worse",
  "addressed_root_cause": "yes|partial|no|unknown",
  "before_after_delta": "1-2 line factual diff (CPU 92% → 14%, sshd auth failures stopped)",
  "evidence": [
    "CPU dropped from 92% at 10:14:02 to 14% at 10:14:08",
    "sshd 'authentication failure' lines absent from the most recent log slice"
  ],
  "follow_up_required": false,
  "follow_up_reason": null,
  "next_recommended_action": null,
  "summary_one_line": "Service restarted cleanly; CPU and log error rate dropped to baseline",
  "suggestions": []
}
```

## Field definitions

- `outcome`:
  - `resolved` — metrics/logs confirm the incident's symptoms are gone
  - `partial` — improvement but the symptom persists
  - `no_effect` — script ran but nothing measurable changed (verdict-1 case)
  - `made_worse` — metrics or logs are worse after execution
- `addressed_root_cause`:
  - `yes` — directly fixed the diagnosed cause
  - `partial` — fixed part of it
  - `no` — script ran but did not address the cause (symptom may have paused, cause remains)
  - `unknown` — insufficient evidence
- `evidence` — 2-4 concrete factual statements drawn from the metrics/logs. Empty list only when there's genuinely no signal.
- `follow_up_required`, `follow_up_reason`, `next_recommended_action` — populate when outcome is `partial`, `no_effect`, or `made_worse`. Otherwise `false` / `null` / `null`.
- `summary_one_line` — single sentence shown in the history list as the verdict subtitle. Required.

## Suggestions block (only on `suggest`-mode servers, see prompt context)

If the prompt context says the server's `ai_autonomy_level` is `suggest` AND the outcome is `no_effect` / `made_worse` / `partial` AND `follow_up_required` is true, populate the `suggestions` array with one or more of these action proposals. **Otherwise leave it empty `[]`.**

```json
{ "action": "disable_script_for_server", "reason": "concrete reason citing evidence" }
{ "action": "disable_rule_for_server",   "reason": "concrete reason citing evidence" }
{
  "action": "suggest_manual_remediation",
  "reason": "why automation can't fix this",
  "manual_commands": [
    {
      "command": "Get-Service WinRM",
      "purpose": "Verify the WinRM service is running",
      "expected_output": "Status : Running",
      "steps": ["Open Admin PowerShell on the VM", "Run the command", "If Stopped: Start-Service WinRM"],
      "risk_level": "low",
      "os_type": "windows"
    }
  ]
}
```

**Phase 28.5 — per-server library actions.** Only when the prompt context says
the server's `script_library_mode` allows server-scoped scripts (or you're
proposing the flip), you may additionally propose:

```json
{
  "action": "swap_remediation_script",
  "reason": "the global script's <X> step is wrong on this server because <Y>",
  "rule_id": "<rule that fired>",
  "language": "bash|powershell|python",
  "target_os": "linux|windows",
  "new_script_content": "<full replacement script — keep the SAME name as the global one>"
}
{
  "action": "create_server_script",
  "reason": "the global library doesn't cover <X> on this server",
  "name": "<distinct new script name>",
  "description": "<short purpose>",
  "language": "bash|powershell|python",
  "content": "<full script body>",
  "target_os": "linux|windows",
  "category": "diagnostic|containment|recovery"
}
```

Approval of either auto-flips the server's `script_library_mode` from
`global` to `both` so the new script actually runs. Use `swap_remediation_script`
when the existing global remediation is *almost right* but needs server-specific
tweaks; use `create_server_script` when proposing a brand-new helper.

Each suggestion will be queued as a separate `ai_actions` row for operator approval. Be concrete; cite the specific evidence that motivated the suggestion. Only emit suggestions when the data clearly points to one — empty array is correct when the verdict is `resolved` or when the cause is unclear.

**Be honest.** If the script obviously didn't work, say `no_effect` — the counting-based recurrence detector elsewhere in the platform takes hours to catch that, and your verdict is the fast signal. If the data is thin, lower confidence rather than inventing a verdict.
"""


def _extract_json_block(text: str) -> Optional[dict]:
    matches = list(re.finditer(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL))
    if not matches:
        return None
    try:
        return json.loads(matches[-1].group(1))
    except Exception:
        return None


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


async def _fetch_review_context(automation_log_id: str) -> Optional[dict]:
    """
    Pull incident + script + server context needed for the review prompt.
    Returns None when any of the prerequisite docs are missing (logged but not
    re-raised — the caller persists a `review_failed` marker).
    """
    db = get_database()
    try:
        log = await db["automation_logs"].find_one({"_id": ObjectId(automation_log_id)})
    except Exception:
        return None
    if not log:
        return None

    incident_id = log.get("incident_id")
    script_id = log.get("script_id")
    server_id = log.get("server_id")

    incident_doc: dict = {}
    rule_name = ""
    if incident_id:
        try:
            incident_doc = await db["incidents"].find_one({"_id": ObjectId(incident_id)}) or {}
        except Exception:
            incident_doc = {}
        rule_id = incident_doc.get("rule_id")
        if rule_id:
            try:
                rule_doc = await db["rules"].find_one({"_id": ObjectId(str(rule_id))}, {"name": 1, "severity": 1})
                if rule_doc:
                    rule_name = rule_doc.get("name", "")
            except Exception:
                pass

    script_doc: dict = {}
    if script_id:
        try:
            script_doc = await db["scripts"].find_one({"_id": ObjectId(script_id)}) or {}
        except Exception:
            script_doc = {}

    server_doc: dict = {}
    if server_id:
        try:
            server_doc = await db["servers"].find_one(
                {"_id": ObjectId(server_id)},
                {"hostname": 1, "os_type": 1, "ai_autonomy_level": 1, "status": 1, "is_online": 1},
            ) or {}
        except Exception:
            server_doc = {}

    return {
        "log": log,
        "incident": incident_doc,
        "rule_name": rule_name,
        "script": script_doc,
        "server": server_doc,
    }


def _build_review_user_message(
    *,
    ctx: dict,
    pre_snapshot: dict,
    post_snapshot: dict,
    review_logs: dict,
) -> str:
    log = ctx["log"]
    incident = ctx["incident"]
    script = ctx["script"]
    server = ctx["server"]
    rule_name = ctx["rule_name"]

    autonomy = server.get("ai_autonomy_level", "read_only")
    server_id = log.get("server_id", "")
    script_content = (script.get("content") or "")[:3000]
    stdout = (log.get("output") or "")[:2000]
    stderr = (log.get("error") or "")[:1000]
    status = log.get("status", "")
    executed_at = log.get("executed_at", "")

    incident_block = (
        f"- **Rule**: {rule_name or incident.get('rule_id', '?')}\n"
        f"- **Severity**: {incident.get('severity', '?')}\n"
        f"- **Detected at**: {incident.get('detected_at', '?')}\n"
        f"- **Status**: {incident.get('status', '?')}\n"
        f"- **Description**: {incident.get('description', '?')}\n"
        f"- **Triggering context**: {json.dumps(incident.get('context') or {})[:500]}\n"
    )

    script_block = (
        f"- **Name**: {script.get('name', '?')}\n"
        f"- **Language**: {script.get('language', '?')}\n"
        f"- **Category**: {script.get('category', '?')}\n"
        f"- **Target OS**: {script.get('target_os', '?')}\n\n"
        f"**Content (truncated to 3000 chars):**\n```{script.get('language', '')}\n{script_content}\n```"
    )

    pre_metrics = pre_snapshot.get("metrics_window") or []
    post_metrics = post_snapshot.get("metrics_window") or []
    pre_state = pre_snapshot.get("server_state") or {}
    post_state = post_snapshot.get("server_state") or {}

    at_source = (review_logs or {}).get("at_source") or []
    latest = (review_logs or {}).get("latest") or []

    autonomy_note = (
        "**This server is in `suggest` mode** — if the outcome is `partial`, "
        "`no_effect`, or `made_worse` AND `follow_up_required` is true, you SHOULD "
        "populate the `suggestions` array with concrete proposals (see system prompt)."
        if autonomy == "suggest"
        else "**This server is in `read_only` mode** — leave the `suggestions` array empty `[]`."
    )

    return (
        f"# Script execution review request\n\n"
        f"An automated remediation script just ran on server `{server.get('hostname') or server_id}`. {autonomy_note}\n\n"
        f"## 1. Incident\n{incident_block}\n"
        f"## 2. Script\n{script_block}\n\n"
        f"## 3. Execution outcome\n"
        f"- **Status**: {status}\n"
        f"- **Executed at**: {executed_at}\n"
        f"- **stdout** (truncated 2000 chars):\n```\n{stdout}\n```\n"
        f"- **stderr** (truncated 1000 chars):\n```\n{stderr}\n```\n\n"
        f"## 4. Pre-snapshot (anchor {pre_snapshot.get('anchor', '?')})\n"
        f"- **Server**: {pre_state.get('hostname', '?')} · online={pre_state.get('is_online', '?')} · status={pre_state.get('status', '?')}\n\n"
        f"{_fmt_metrics_table(pre_metrics)}\n\n"
        f"## 5. Post-snapshot (anchor {post_snapshot.get('anchor', '?')}, after ~{REMEDIATION_SETTLING_SECONDS}s settling delay)\n"
        f"- **Server**: {post_state.get('hostname', '?')} · online={post_state.get('is_online', '?')} · status={post_state.get('status', '?')}\n\n"
        f"{_fmt_metrics_table(post_metrics)}\n\n"
        f"## 6. Logs evidence (deduplicated by ES `_id` — no entry in both slices)\n\n"
        f"### 6a. Logs at the source alert time (up to 10: 5 before + 5 after)\n"
        f"{_fmt_log_lines(at_source)}\n\n"
        f"### 6b. Most recent logs (up to 10, latest first)\n"
        f"{_fmt_log_lines(list(reversed(latest)))}\n\n"
        f"---\n\n"
        f"Now produce the review. End with the ```json block exactly as specified in your system prompt."
    )


async def _queue_suggestion_actions(
    *,
    suggestions: list,
    run_id: str,
    analysis_id: str,
    automation_log_id: str,
    incident_id: str,
    server_id: str,
    script_id: str,
    rule_id: str,
) -> int:
    """
    Insert one `ai_actions` row per AI-emitted suggestion. Returns the count
    inserted. Each action carries enough payload that the approval endpoint
    can perform the underlying mutation without re-running the LLM.
    """
    if not suggestions:
        return 0

    db = get_database()
    now = utc_now()
    rows = []

    for sug in suggestions:
        if not isinstance(sug, dict):
            continue
        action = sug.get("action")
        reason = sug.get("reason") or ""
        if action == "disable_script_for_server":
            payload = {
                "server_id": server_id,
                "script_id": script_id,
                "reason": reason[:500],
                "ai_analysis_id": analysis_id,
                "automation_log_id": automation_log_id,
            }
        elif action == "disable_rule_for_server":
            payload = {
                "server_id": server_id,
                "rule_id": rule_id,
                "reason": reason[:500],
                "ai_analysis_id": analysis_id,
                "automation_log_id": automation_log_id,
            }
        elif action == "suggest_manual_remediation":
            manual_commands = sug.get("manual_commands") or []
            # Defensive shape clamp — drop anything malformed so the UI never blows up.
            cleaned: list[dict] = []
            for mc in manual_commands[:8]:
                if not isinstance(mc, dict):
                    continue
                cleaned.append({
                    "command": str(mc.get("command", ""))[:1000],
                    "purpose": str(mc.get("purpose", ""))[:300],
                    "expected_output": str(mc.get("expected_output", ""))[:300] or None,
                    "steps": [str(s)[:200] for s in (mc.get("steps") or [])][:10] or None,
                    "risk_level": mc.get("risk_level") if mc.get("risk_level") in ("low", "medium", "high") else None,
                    "os_type": mc.get("os_type") if mc.get("os_type") in ("linux", "windows") else None,
                })
            payload = {
                "server_id": server_id,
                "incident_id": incident_id,
                "manual_commands": cleaned,
                "reason": reason[:500],
                "ai_analysis_id": analysis_id,
                "automation_log_id": automation_log_id,
            }
        # Phase 28.5 — per-server library actions
        elif action == "create_server_rule":
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
                "reason": reason[:500],
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
                "reason": reason[:500],
                "ai_analysis_id": analysis_id,
            }
        elif action == "swap_remediation_script":
            payload = {
                "server_id": server_id,
                "rule_id": sug.get("rule_id") or rule_id,
                "new_script_content": str(sug.get("new_script_content", ""))[:20000],
                "language": sug.get("language") if sug.get("language") in ("bash", "powershell", "python") else "bash",
                "target_os": sug.get("target_os") if sug.get("target_os") in ("linux", "windows") else "linux",
                "reason": reason[:500],
                "ai_analysis_id": analysis_id,
            }
        else:
            continue

        rows.append({
            "action_type": action,
            "payload": payload,
            "run_id": run_id,
            "source_type": "automation_log",
            "source_id": automation_log_id,
            "server_id": server_id,
            "status": "pending",
            "created_at": now,
            "decided_at": None,
            "decided_by": None,
        })

    if not rows:
        return 0

    await db["ai_actions"].insert_many(rows)
    # Tell the AI Actions inbox to refresh its badge / list.
    try:
        event_bus.emit("ai_actions", "ai_action.created", {
            "server_id": server_id,
            "automation_log_id": automation_log_id,
            "count": len(rows),
        })
    except Exception:
        pass
    return len(rows)


async def run_script_execution_review(
    *,
    automation_log_id: str,
    pre_snapshot: dict,
    post_snapshot: dict,
) -> None:
    """
    Fire-and-forget AI review for a single automation_logs row.

    Runs the LLM, saves an `ai_analysis` row of type `script_execution_review`,
    denormalises `ai_review_id`/`ai_review_verdict`/`ai_review_summary` back onto
    `automation_logs`, emits `automation_review_ready` on the per-server WS topic,
    and queues `ai_actions` suggestions if the server is in `suggest` mode.

    Exceptions are caught and persisted as `ai_review_verdict="review_failed"`
    so the UI shows a clear "review unavailable" state instead of hanging.
    """
    db = get_database()
    ctx = await _fetch_review_context(automation_log_id)
    if not ctx:
        await db["automation_logs"].update_one(
            {"_id": ObjectId(automation_log_id)},
            {"$set": {"ai_review_verdict": "review_failed", "ai_review_summary": "Context not found"}},
        )
        return

    log = ctx["log"]
    server_id = log.get("server_id", "")
    incident_id = log.get("incident_id", "")
    script_id = log.get("script_id", "")
    rule_id = str(ctx["incident"].get("rule_id") or "")
    autonomy = ctx["server"].get("ai_autonomy_level", "read_only")
    run_id = str(uuid.uuid4())[:8]

    # Phase 28.5 — mark in-progress immediately so the detail page's
    # "analysisRunning" flag is true on first render. Cleared in the happy path
    # below when the verdict is persisted, or in the except branch on failure.
    await db["automation_logs"].update_one(
        {"_id": ObjectId(automation_log_id)},
        {"$set": {
            "ai_review_verdict": "in_progress",
            "ai_review_summary": "Analysis running…",
        }},
    )

    try:
        # Logs anchored on the pre-snapshot moment (= just before the script ran),
        # mirroring the impact-agent pattern.
        anchor_iso = pre_snapshot.get("anchor")
        try:
            source_anchor = datetime.fromisoformat(anchor_iso) if anchor_iso else utc_now()
        except Exception:
            source_anchor = utc_now()
        if source_anchor.tzinfo is None:
            source_anchor = source_anchor.replace(tzinfo=timezone.utc)
        review_logs = await fetch_review_logs(server_id, source_anchor=source_anchor)

        user_message = _build_review_user_message(
            ctx=ctx,
            pre_snapshot=pre_snapshot,
            post_snapshot=post_snapshot,
            review_logs=review_logs,
        )

        # Phase 28.5 — streaming refactor. The review is grounded in pre-fetched
        # context (no tool calls) so we use `astream` rather than the heavier
        # `astream_events`; same WS-emit pattern as `triage_graph` / `server_graph`
        # so the new remediation detail page can subscribe via `useAiAnalysisStream`.
        model = get_chat_model()

        # Initial empty token kicks the frontend's stream state into "running".
        try:
            event_bus.emit(f"servers.{server_id}.ai", "ai_analysis_token", {
                "run_id": run_id,
                "source_type": "automation_log",
                "source_id": automation_log_id,
                "token": "",
            })
        except Exception:
            pass

        stream_chunks: list[str] = []
        async for chunk in model.astream([
            {"role": "system", "content": SCRIPT_REVIEW_SYSTEM_PROMPT},
            HumanMessage(content=user_message),
        ]):
            content = getattr(chunk, "content", None)
            token_text = ""
            if isinstance(content, str):
                token_text = content
            elif isinstance(content, list):
                try:
                    token_text = "".join(
                        p.get("text", "") if isinstance(p, dict) else str(p)
                        for p in content
                    )
                except Exception:
                    token_text = ""
            if not token_text:
                continue
            stream_chunks.append(token_text)
            try:
                event_bus.emit(f"servers.{server_id}.ai", "ai_analysis_token", {
                    "run_id": run_id,
                    "source_type": "automation_log",
                    "source_id": automation_log_id,
                    "token": token_text,
                })
            except Exception:
                pass

        raw_text = ("".join(stream_chunks)).strip()
        parsed = _extract_json_block(raw_text) or {}

        outcome = parsed.get("outcome", "no_effect")
        addressed = parsed.get("addressed_root_cause", "unknown")
        before_after_delta = parsed.get("before_after_delta", "") or ""
        evidence = parsed.get("evidence", []) or []
        summary_one_line = (parsed.get("summary_one_line") or before_after_delta or outcome)[:200]
        suggestions = parsed.get("suggestions") or []

        markdown = f"## AI Script Execution Review\n\n{raw_text}\n\n---\n*automation_log: {automation_log_id}*"

        analysis_id = await save_analysis(
            run_id=run_id,
            analysis_type="script_execution_review",
            source_type="automation_log",
            source_id=automation_log_id,
            server_id=server_id,
            summary=summary_one_line,
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
                "summary_one_line": summary_one_line,
                "suggestions": suggestions,
                "incident_id": incident_id,
                "script_id": script_id,
                "rule_id": rule_id,
            },
            anchored_at=datetime.now(timezone.utc),
            window_minutes=0,
            llm_provider=settings.LLM_PROVIDER,
            llm_model=settings.LLM_MODEL,
        )

        # Denormalise pointer + verdict back onto the automation_logs row.
        # `save_analysis` already wrote `ai_analysis_latest_id` + count via
        # _source_collection mapping; the three review fields are extra.
        await db["automation_logs"].update_one(
            {"_id": ObjectId(automation_log_id)},
            {"$set": {
                "ai_review_id": analysis_id,
                "ai_review_verdict": outcome,
                "ai_review_summary": summary_one_line,
            }},
        )

        # Queue suggestion actions when the server is in suggest mode AND the
        # LLM produced concrete proposals.
        suggested_count = 0
        if autonomy == "suggest" and suggestions:
            suggested_count = await _queue_suggestion_actions(
                suggestions=suggestions,
                run_id=run_id,
                analysis_id=analysis_id,
                automation_log_id=automation_log_id,
                incident_id=incident_id,
                server_id=server_id,
                script_id=script_id,
                rule_id=rule_id,
            )

        # WS — refresh the history list + incident detail page on the per-server
        # topic. The frontend's existing `servers.{id}.automation` invalidator
        # already subscribes here.
        payload = {
            "automation_log_id": automation_log_id,
            "incident_id": incident_id,
            "verdict": outcome,
            "summary": summary_one_line,
            "analysis_id": analysis_id,
            "suggested_actions": suggested_count,
        }
        try:
            event_bus.emit(f"servers.{server_id}.automation", "automation_review_ready", payload)
        except Exception:
            pass
        try:
            event_bus.emit("automation.history", "automation_review_ready", payload)
        except Exception:
            pass

        # Phase 28.5 — signal stream completion so `useAiAnalysisStream` flips
        # `streamCompleted=true` and the typing cursor disappears.
        try:
            event_bus.emit(f"servers.{server_id}.ai", "ai_analysis_complete", {
                "run_id": run_id,
                "source_type": "automation_log",
                "source_id": automation_log_id,
                "analysis_id": analysis_id,
            })
        except Exception:
            pass

    except Exception as exc:
        # Persist a failure marker so the UI shows "review unavailable" instead
        # of an indefinite spinner. The underlying script execution is unaffected
        # — it already completed before this function ran.
        msg = f"{type(exc).__name__}: {exc}"[:200]
        try:
            await db["automation_logs"].update_one(
                {"_id": ObjectId(automation_log_id)},
                {"$set": {"ai_review_verdict": "review_failed", "ai_review_summary": msg}},
            )
        except Exception:
            pass
        # Phase 28.5 — break the frontend's running state so the failure marker
        # actually renders (otherwise the stream hook keeps showing the cursor).
        try:
            event_bus.emit(f"servers.{server_id}.ai", "ai_analysis_complete", {
                "run_id": run_id,
                "source_type": "automation_log",
                "source_id": automation_log_id,
                "analysis_id": None,
                "error": msg,
            })
        except Exception:
            pass


async def run_review_with_settling(
    *,
    automation_log_id: str,
    server_id: str,
    pre_snapshot: dict,
) -> None:
    """
    Background entry point invoked via `asyncio.create_task` from
    `execute_remediation`. Sleeps the settling window so post-execution logs
    and metrics can land, captures the post-snapshot, then dispatches to the
    review function above.
    """
    try:
        await asyncio.sleep(REMEDIATION_SETTLING_SECONDS)
        post_snapshot = await capture_snapshot(server_id, anchor=utc_now())
        await run_script_execution_review(
            automation_log_id=automation_log_id,
            pre_snapshot=pre_snapshot,
            post_snapshot=post_snapshot,
        )
    except Exception as exc:
        db = get_database()
        msg = f"{type(exc).__name__}: {exc}"[:200]
        try:
            await db["automation_logs"].update_one(
                {"_id": ObjectId(automation_log_id)},
                {"$set": {"ai_review_verdict": "review_failed", "ai_review_summary": msg}},
            )
        except Exception:
            pass
