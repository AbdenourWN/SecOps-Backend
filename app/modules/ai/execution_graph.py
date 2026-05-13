"""
AI command execution graph.

Entry point: run_execution_batch(batch_id, command_ids)

For each approved command in sequence:
  1. Check guardrails (block list / rate limit)
  2. Capture pre_snapshot (metrics + log tail)
  3. Execute via terminal_pool
  4. Capture post_snapshot
  5. Run impact agent → save to ai_analysis (analysis_type="command_impact")
  6. Denormalize verdict + summary onto ai_command row
"""
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.events import event_bus
from app.modules.servers.guardrails import check_command
from app.modules.ai.llm import get_chat_model
from app.modules.ai.analysis_store import save_analysis
from app.modules.ai.tools_read import ALL_READ_TOOLS


IMPACT_SYSTEM_PROMPT = """You are a SOC analyst reviewing the result of a remediation command that was just executed on a server.

You receive:
- The command that was run, its purpose and expected outcome
- The server's state BEFORE execution (metrics + log tail)
- The command's stdout/stderr/exit_code
- The server's state AFTER execution

Your job: determine whether the command worked and what changed.

Write a short analysis in Markdown (3-5 sentences), then end with a ```json block:
```json
{
  "outcome": "resolved|partial|no_effect|made_worse",
  "before_after_delta": "1-2 line factual diff (e.g. CPU 92% → 14%, sshd auth failures stopped)",
  "follow_up_required": false,
  "follow_up_reason": null,
  "next_recommended_action": null
}
```

Outcome definitions:
- resolved: the root cause appears fixed (metrics/logs confirm improvement)
- partial: improvement but issue persists
- no_effect: command ran successfully but nothing measurable changed
- made_worse: metrics or logs indicate degradation after execution
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


async def _capture_snapshot(server_id: str) -> dict:
    """Capture a lightweight server snapshot: cached metrics + last 10 log lines."""
    db = get_database()
    now = utc_now()
    metrics = {}
    try:
        srv = await db["servers"].find_one({"_id": ObjectId(server_id)}, {"last_metrics": 1, "open_incidents_count": 1})
        if srv:
            lm = srv.get("last_metrics") or {}
            metrics = {
                "cpu_usage": lm.get("cpu_usage"),
                "ram_usage": lm.get("ram_usage"),
                "disk_usage": lm.get("disk_usage"),
                "collected_at": str(lm.get("collected_at", "")),
            }
    except Exception:
        pass

    open_incidents_count = 0
    try:
        open_incidents_count = await db["incidents"].count_documents(
            {"server_id": server_id, "status": {"$in": ["open", "verifying"]}}
        )
    except Exception:
        pass

    log_tail = []
    try:
        cursor = db["logs"].find({"server_id": server_id}).sort("timestamp", -1).limit(10)
        logs = await cursor.to_list(length=10)
        log_tail = [
            {
                "timestamp": str(l.get("timestamp", "")),
                "level": l.get("level", ""),
                "message": (l.get("message", "") or "")[:200],
            }
            for l in reversed(logs)
        ]
    except Exception:
        pass

    return {
        "metrics": metrics,
        "log_tail": log_tail,
        "open_incidents_count": open_incidents_count,
        "timestamp": now.isoformat(),
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


async def _run_impact_agent(
    command: str,
    purpose: str,
    expected_outcome: str,
    stdout: str,
    stderr: str,
    exit_code: Optional[int],
    pre_snapshot: dict,
    post_snapshot: dict,
    server_id: str,
    command_id: str,
    run_id: str,
    analysis_id_triage: str,
) -> dict:
    """Run the impact analysis LLM for one command. Returns analysis_id + verdict."""
    model = get_chat_model()
    agent = create_react_agent(model=model, tools=list(ALL_READ_TOOLS), prompt=IMPACT_SYSTEM_PROMPT)

    pre_str = json.dumps(pre_snapshot, default=str)
    post_str = json.dumps(post_snapshot, default=str)
    stdout_snippet = (stdout or "")[:2000]
    stderr_snippet = (stderr or "")[:500]

    result = await agent.ainvoke({
        "messages": [
            HumanMessage(
                content=(
                    f"A command was just executed on server (server_id={server_id}).\n\n"
                    f"**Command:** `{command}`\n"
                    f"**Purpose:** {purpose}\n"
                    f"**Expected outcome:** {expected_outcome}\n\n"
                    f"**Exit code:** {exit_code}\n"
                    f"**stdout:**\n```\n{stdout_snippet}\n```\n"
                    f"**stderr:**\n```\n{stderr_snippet}\n```\n\n"
                    f"**Before execution state:**\n{pre_str}\n\n"
                    f"**After execution state:**\n{post_str}\n\n"
                    f"Assess the impact. Use read tools only if you need more context. "
                    f"End with the ```json block."
                )
            )
        ]
    })

    messages = result.get("messages", [])
    raw_text = _extract_final_text(messages)
    parsed = _extract_json_block(raw_text) or {}

    outcome = parsed.get("outcome", "no_effect")
    before_after_delta = parsed.get("before_after_delta", "")
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
            "before_after_delta": before_after_delta,
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
        run_id = cmd_doc.get("run_id", str(uuid.uuid4())[:8])

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

        # Pre-snapshot
        pre_snapshot = await _capture_snapshot(server_id)
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

        # Post-snapshot
        post_snapshot = await _capture_snapshot(server_id)
        await db["ai_command"].update_one(
            {"_id": ObjectId(command_id)},
            {"$set": {"post_snapshot": post_snapshot}},
        )

        # Impact agent — skip if the command never reached the server (no output at all)
        if status == "completed" or (status == "failed" and (stdout or stderr)):
            try:
                impact = await _run_impact_agent(
                    command=command,
                    purpose=purpose,
                    expected_outcome=expected_outcome,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    pre_snapshot=pre_snapshot,
                    post_snapshot=post_snapshot,
                    server_id=server_id,
                    command_id=command_id,
                    run_id=run_id,
                    analysis_id_triage=cmd_doc.get("analysis_id", ""),
                )
                await db["ai_command"].update_one(
                    {"_id": ObjectId(command_id)},
                    {"$set": {
                        "impact_analysis_id": impact["analysis_id"],
                        "impact_verdict": impact["outcome"],
                        "impact_summary": impact["before_after_delta"][:200] if impact["before_after_delta"] else "",
                    }},
                )
                _emit_progress(server_id, command_id, "report_ready", verdict=impact["outcome"])
            except Exception as e:
                _emit_progress(server_id, command_id, "report_error", error=str(e))

        results.append({"command_id": command_id, "status": status})

    return {"batch_id": batch_id, "results": results}
