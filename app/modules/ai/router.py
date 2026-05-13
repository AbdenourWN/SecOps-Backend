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
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    """List AI pending/completed actions, newest first."""
    db = get_database()
    query: dict = {}
    if status and status != "all":
        query["status"] = status
    else:
        query["status"] = {"$in": ["pending", "approved", "rejected"]}

    total = await db["ai_actions"].count_documents(query)
    skip = (page - 1) * page_size
    docs = await db["ai_actions"].find(query).sort("created_at", -1).skip(skip).limit(page_size).to_list(length=page_size)
    return {"total": total, "page": page, "page_size": page_size, "results": [_fmt(d) for d in docs]}


@router.get("/count")
async def pending_action_count():
    """Count of pending (unresolved) AI actions — used for sidebar badge."""
    db = get_database()
    count = await db["ai_actions"].count_documents({"status": "pending"})
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
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    """List ai_command rows with optional filters."""
    return await list_commands(
        status=status,
        server_id=server_id,
        source_id=source_id,
        source_type=source_type,
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
    limit: int = Query(20, ge=1, le=100),
):
    """List ai_analysis rows. Filter by source or server."""
    if source_id and source_type:
        return await list_analyses_for_source(source_type, source_id, analysis_type, limit)
    if server_id:
        return await list_server_analyses(server_id, analysis_type, limit)
    # Return recent analyses if no filter given
    db = get_database()
    query: dict = {}
    if analysis_type:
        query["analysis_type"] = analysis_type
    cursor = db["ai_analysis"].find(query).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


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

    action = await db["ai_actions"].find_one({"_id": oid, "status": "pending"})
    if not action:
        raise HTTPException(status_code=404, detail="Pending action not found")

    payload = action.get("payload", {})
    action_type = action.get("action_type", "")

    outcome = {"executed": False, "error": "Unknown action_type"}
    try:
        if action_type == "dismiss_anomaly":
            outcome = await _execute_dismiss_anomaly(payload["observation_id"], payload.get("reason", ""))
        elif action_type == "promote_anomaly":
            outcome = await _execute_promote_anomaly(payload["observation_id"])
        elif action_type == "mark_incident_false_positive":
            outcome = await _execute_mark_incident_false_positive(payload["incident_id"], payload.get("reason", ""))
    except Exception as exc:
        outcome = {"executed": False, "error": str(exc)}

    now = utc_now()
    await db["ai_actions"].update_one(
        {"_id": oid},
        {"$set": {"status": "approved", "decided_at": now, "decided_by": decided_by, "outcome": outcome}},
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

    result = await db["ai_actions"].update_one(
        {"_id": oid, "status": "pending"},
        {"$set": {"status": "rejected", "decided_at": utc_now(), "decided_by": decided_by}},
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Pending action not found or already decided")
    return {"status": "rejected", "action_id": action_id}
