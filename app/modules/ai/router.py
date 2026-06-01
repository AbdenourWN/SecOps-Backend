"""
AI actions router.

Mutation-approval inbox (ai_actions — dismiss/promote/mark-false-positive):
  GET  /api/ai-actions/              list
  GET  /api/ai-actions/count         pending badge count
  POST /api/ai-actions/{id}/approve  execute + mark approved
  POST /api/ai-actions/{id}/reject   mark rejected

Command approval + execution (ai_command):
  POST /api/ai-actions/commands/approve   body: {command_ids: [str]}
  POST /api/ai-actions/commands/reject    body: {command_ids: [str]}
  GET  /api/ai-actions/commands           list with filters
  GET  /api/ai-actions/commands/count     pending command count
  GET  /api/ai-actions/commands/{id}      single command detail

AI analysis history:
  GET  /api/ai-actions/analysis           list analyses (filter: source_type, source_id, server_id, analysis_type)
  GET  /api/ai-actions/analysis/{id}      single analysis detail
"""
from app.core.constants import Collections, ActionType, ActionStatus
from app.core.db_utils import build_date_range_query, enrich_with_server_hostname
import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.modules.ai.tools_mutate import (
    _execute_dismiss_anomaly,
    _execute_promote_anomaly,
    _execute_mark_incident_false_positive,
    _execute_disable_script_for_server,
    _execute_disable_rule_for_server,
    _execute_suggest_manual_remediation,
    # Phase 28.5 — per-server library actions
    _execute_create_server_rule,
    _execute_create_server_script,
    _execute_swap_remediation_script,
    # Phase 28.5.4 — atomic rule+script pair
    _execute_create_server_rule_with_script,
)
from app.modules.ai.command_store import (
    approve_commands,
    reject_commands,
    list_commands,
    get_command,
    pending_count as commands_pending_count,
    retry_command,
)
from app.modules.ai.analysis_store import (
    get_analysis_by_id,
    list_analyses_for_source,
    list_server_analyses,
)


class ApproveCommandsBody(BaseModel):
    command_ids: List[str]
    decided_by: str = "operator"


class RejectCommandsBody(BaseModel):
    command_ids: List[str]
    decided_by: str = "operator"

router = APIRouter()


def _fmt(doc: dict) -> dict:
    doc["_id"] = str(doc["_id"])
    return doc


@router.get("/")
async def list_ai_actions(
    status: Optional[str] = Query(None, description="pending | approved | rejected | all"),
    server_id: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None, description="incident | anomaly | all"),
    source_id: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, description="ISO datetime — filter on created_at >= this time"),
    to_date: Optional[str] = Query(None, description="ISO datetime — filter on created_at <= this time"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    """List AI pending/completed actions, newest first. Enriched with server_hostname."""
    db = get_database()
    query: dict = {}
    if status and status != "all":
        query["status"] = status
    else:
        query["status"] = {"$in": ["pending", "approved", "rejected"]}
    if server_id:
        query["server_id"] = server_id
    if source_type and source_type != "all":
        query["source_type"] = source_type
    if source_id:
        query["source_id"] = source_id
    date_range = build_date_range_query(from_date, to_date)
    if date_range:
        query["created_at"] = date_range

    total = await db[Collections.AI_ACTIONS].count_documents(query)
    skip = (page - 1) * page_size
    # For decided rows we want "most recently decided" at the top; for pending,
    # the only meaningful timestamp is created_at. decided_at is null for pending,
    # so this composite sort lands on the right answer in both filters.
    docs = await db[Collections.AI_ACTIONS].find(query).sort([
        ("decided_at", -1),
        ("created_at", -1),
    ]).skip(skip).limit(page_size).to_list(length=page_size)

    # Batch-enrich with server hostname so the UI doesn't need a second round-trip per row
    out = [_fmt(d) for d in docs]
    await enrich_with_server_hostname(out, db)

    return {"total": total, "page": page, "page_size": page_size, "results": out}


@router.get("/count")
async def pending_action_count(
    source_type: Optional[str] = Query(None),
    source_id: Optional[str] = Query(None),
):
    """Count of pending (unresolved) AI actions — used for sidebar badge and per-source counters."""
    db = get_database()
    query: dict = {"status": "pending"}
    if source_type and source_type != "all":
        query["source_type"] = source_type
    if source_id:
        query["source_id"] = source_id
    count = await db[Collections.AI_ACTIONS].count_documents(query)
    return {"pending": count}


# ── Command approval / execution endpoints ────────────────────────────────────
# NOTE: These static /commands/* and /analysis/* routes MUST be registered
# before the dynamic /{action_id}/* routes below, otherwise FastAPI's router
# matches "/commands/approve" as action_id="commands".

@router.post("/commands/approve")
async def approve_command_batch(body: ApproveCommandsBody):
    """
    Approve a list of pending ai_command rows and kick off execution.
    All commands in the list share a batch_id and run sequentially.
    """
    if not body.command_ids:
        raise HTTPException(status_code=400, detail="command_ids required")

    batch_id = await approve_commands(body.command_ids, decided_by=body.decided_by)

    # Dispatch execution in background (non-blocking for the HTTP response)
    from app.modules.ai.execution_graph import run_execution_batch
    asyncio.create_task(run_execution_batch(batch_id, body.command_ids))

    return {"status": "approved", "batch_id": batch_id, "command_count": len(body.command_ids)}


@router.post("/commands/reject")
async def reject_command_batch(body: RejectCommandsBody):
    """Reject a list of pending ai_command rows (no execution)."""
    if not body.command_ids:
        raise HTTPException(status_code=400, detail="command_ids required")
    await reject_commands(body.command_ids, decided_by=body.decided_by)
    return {"status": "rejected", "count": len(body.command_ids)}


@router.get("/commands/count")
async def command_pending_count():
    """Number of pending ai_command rows — for sidebar badge."""
    count = await commands_pending_count()
    return {"pending": count}


@router.get("/commands")
async def list_ai_commands(
    status: Optional[str] = Query(None),
    server_id: Optional[str] = Query(None),
    source_id: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None),
    to_date: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    """List ai_command rows with optional filters. Date filter applies on `created_at`."""
    return await list_commands(
        status=status,
        server_id=server_id,
        source_id=source_id,
        source_type=source_type,
        from_date=from_date,
        to_date=to_date,
        page=page,
        page_size=page_size,
    )


@router.get("/commands/{command_id}")
async def get_ai_command(command_id: str):
    """Get a single ai_command row with full lifecycle detail."""
    doc = await get_command(command_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Command not found")
    return doc


@router.post("/commands/{command_id}/retry")
async def retry_ai_command(command_id: str, decided_by: str = "operator"):
    """
    Clone a failed/blocked command into a new pending row and immediately approve+dispatch it.
    Returns the new command_id and batch_id.
    """
    try:
        new_id = await retry_command(command_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    batch_id = await approve_commands([new_id], decided_by=decided_by)

    from app.modules.ai.execution_graph import run_execution_batch
    asyncio.create_task(run_execution_batch(batch_id, [new_id]))

    return {"status": "queued", "new_command_id": new_id, "batch_id": batch_id}


# ── AI analysis history endpoints ─────────────────────────────────────────────

@router.get("/analysis")
async def list_ai_analyses(
    source_type: Optional[str] = Query(None),
    source_id: Optional[str] = Query(None),
    server_id: Optional[str] = Query(None),
    analysis_type: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, description="ISO datetime — filter on created_at >= this time"),
    to_date: Optional[str] = Query(None, description="ISO datetime — filter on created_at <= this time"),
    page: Optional[int] = Query(None, ge=1),
    page_size: Optional[int] = Query(None, ge=1, le=100),
    limit: int = Query(20, ge=1, le=100),
):
    """
    List ai_analysis rows.

    Two call shapes are supported:
      - Legacy (no `page`): returns a flat list, length capped by `limit`.
        Kept so existing source-detail panels keep working unchanged.
      - Paginated (`page` provided): returns
        `{total, page, page_size, results}` with rows enriched with
        `server_hostname` (batched). Used by the new /ai-analyses index page.
    Date filters apply on `created_at`.
    """
    db = get_database()
    paginated = page is not None

    query: dict = {}
    if source_type and source_type != "all":
        query["source_type"] = source_type
    if source_id:
        query["source_id"] = source_id
    if server_id:
        query["server_id"] = server_id
    if analysis_type and analysis_type != "all":
        query["analysis_type"] = analysis_type
    date_range = build_date_range_query(from_date, to_date)
    if date_range:
        query["created_at"] = date_range

    if not paginated:
        # Legacy unpaginated shape — preserved for existing callers
        if source_id and source_type:
            return await list_analyses_for_source(source_type, source_id, analysis_type, limit)
        if server_id:
            return await list_server_analyses(server_id, analysis_type, limit)
        cursor = db[Collections.AI_ANALYSIS].find(query).sort("created_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs

    size = page_size or 25
    total = await db[Collections.AI_ANALYSIS].count_documents(query)
    skip = (page - 1) * size
    docs = await db[Collections.AI_ANALYSIS].find(query).sort("created_at", -1).skip(skip).limit(size).to_list(length=size)

    # Batch-enrich with server hostname so the list page doesn't need N round-trips
    out = [_fmt(d) for d in docs]
    await enrich_with_server_hostname(out, db)
    return {"total": total, "page": page, "page_size": size, "results": out}


@router.get("/analysis/{analysis_id}")
async def get_ai_analysis(analysis_id: str):
    """Get a single ai_analysis row with full markdown + structured fields."""
    doc = await get_analysis_by_id(analysis_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return doc


# ── Mutation-action dynamic routes — MUST be LAST so static /commands/* paths above match first ──

@router.post("/{action_id}/approve")
async def approve_action(action_id: str, decided_by: str = "operator"):
    """Execute a pending AI mutation action (dismiss/promote/mark-false-positive) and mark it approved."""
    db = get_database()
    try:
        oid = ObjectId(action_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid action_id")

    action = await db[Collections.AI_ACTIONS].find_one({"_id": oid, "status": ActionStatus.PENDING})
    if not action:
        raise HTTPException(status_code=404, detail="Pending action not found")

    payload = action.get("payload", {})
    action_type = action.get("action_type", "")

    outcome = {"executed": False, "error": "Unknown action_type"}
    try:
        if action_type == ActionType.DISMISS_ANOMALY:
            outcome = await _execute_dismiss_anomaly(payload["observation_id"], payload.get("reason", ""))
        elif action_type == ActionType.PROMOTE_ANOMALY:
            outcome = await _execute_promote_anomaly(payload["observation_id"])
        elif action_type == ActionType.MARK_INCIDENT_FALSE_POSITIVE:
            outcome = await _execute_mark_incident_false_positive(payload["incident_id"], payload.get("reason", ""))
        elif action_type == ActionType.DISABLE_SCRIPT_FOR_SERVER:
            outcome = await _execute_disable_script_for_server(
                payload.get("server_id", ""),
                payload.get("script_id", ""),
                payload.get("reason", ""),
            )
        elif action_type == ActionType.DISABLE_RULE_FOR_SERVER:
            outcome = await _execute_disable_rule_for_server(
                payload.get("server_id", ""),
                payload.get("rule_id", ""),
                payload.get("reason", ""),
            )
        elif action_type == ActionType.SUGGEST_MANUAL_REMEDIATION:
            outcome = await _execute_suggest_manual_remediation(
                payload.get("incident_id", ""),
                payload.get("manual_commands", []) or [],
                payload.get("reason", ""),
                payload.get("automation_log_id", "") or "",
            )
        # Phase 28.5 — per-server library actions
        elif action_type == ActionType.CREATE_SERVER_RULE:
            outcome = await _execute_create_server_rule(
                server_id=payload.get("server_id", ""),
                name=payload.get("name", ""),
                pattern=payload.get("pattern", ""),
                severity=payload.get("severity", "medium"),
                action_level=int(payload.get("action_level", 3) or 3),
                description=payload.get("description", ""),
                os_type=payload.get("os_type", "linux"),
                tags=payload.get("tags") or [],
                remediation_script_id=payload.get("remediation_script_id"),
                reason=payload.get("reason", ""),
                ai_analysis_id=payload.get("ai_analysis_id"),
            )
        elif action_type == ActionType.CREATE_SERVER_SCRIPT:
            outcome = await _execute_create_server_script(
                server_id=payload.get("server_id", ""),
                name=payload.get("name", ""),
                description=payload.get("description", ""),
                language=payload.get("language", "bash"),
                content=payload.get("content", ""),
                target_os=payload.get("target_os", "linux"),
                category=payload.get("category", "recovery"),
                reason=payload.get("reason", ""),
                ai_analysis_id=payload.get("ai_analysis_id"),
            )
        elif action_type == ActionType.SWAP_REMEDIATION_SCRIPT:
            outcome = await _execute_swap_remediation_script(
                server_id=payload.get("server_id", ""),
                rule_id=payload.get("rule_id", ""),
                new_script_content=payload.get("new_script_content", ""),
                language=payload.get("language", "bash"),
                target_os=payload.get("target_os", "linux"),
                reason=payload.get("reason", ""),
                ai_analysis_id=payload.get("ai_analysis_id"),
            )
        elif action_type == ActionType.CREATE_SERVER_RULE_WITH_SCRIPT:
            outcome = await _execute_create_server_rule_with_script(
                server_id=payload.get("server_id", ""),
                rule_name=payload.get("rule_name", ""),
                pattern=payload.get("pattern", ""),
                severity=payload.get("severity", "medium"),
                action_level=int(payload.get("action_level", 3) or 3),
                rule_description=payload.get("rule_description", ""),
                os_type=payload.get("os_type", "linux"),
                tags=payload.get("tags") or [],
                script_name=payload.get("script_name", ""),
                script_description=payload.get("script_description", ""),
                language=payload.get("language", "bash"),
                content=payload.get("content", ""),
                target_os=payload.get("target_os", "linux"),
                category=payload.get("category", "recovery"),
                reason=payload.get("reason", ""),
                ai_analysis_id=payload.get("ai_analysis_id"),
            )
    except Exception as exc:
        outcome = {"executed": False, "error": str(exc)}

    now = utc_now()
    await db[Collections.AI_ACTIONS].update_one(
        {"_id": oid},
        {"$set": {"status": ActionStatus.APPROVED, "decided_at": now, "decided_by": decided_by, "outcome": outcome}},
    )
    return {"status": "approved", "action_id": action_id, "outcome": outcome}


@router.post("/{action_id}/reject")
async def reject_action(action_id: str, decided_by: str = "operator"):
    """Reject a pending AI mutation action without executing it."""
    db = get_database()
    try:
        oid = ObjectId(action_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid action_id")

    result = await db[Collections.AI_ACTIONS].update_one(
        {"_id": oid, "status": ActionStatus.PENDING},
        {"$set": {"status": ActionStatus.REJECTED, "decided_at": utc_now(), "decided_by": decided_by}},
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Pending action not found or already decided")
    return {"status": "rejected", "action_id": action_id}
