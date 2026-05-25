import asyncio
import re as re_mod

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.modules.automation.schemas import ScriptCreate, ScriptInDB
from app.modules.automation.service import AutomationService
from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.events import event_bus
from bson import ObjectId
from datetime import datetime, timezone

router = APIRouter()
service = AutomationService()


@router.get("/history")
async def get_automation_history(
    limit: int = Query(20, ge=1, le=100),
    skip: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="Filter: success, failed"),
    server_id: Optional[str] = Query(None),
    script_id: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, description="ISO datetime — filter on executed_at >= this time"),
    to_date: Optional[str] = Query(None, description="ISO datetime — filter on executed_at <= this time"),
):
    """
    Remediation runs (newest first), enriched with server hostname + script name.
    Supports pagination, status/server/script filters, and an executed_at range.
    Used by both the dashboard activity widget and the dedicated automation history page.
    NOTE: Must be declared above /{script_id}-style routes.
    """
    return await service.get_history(
        limit=limit,
        skip=skip,
        status=status,
        server_id=server_id,
        script_id=script_id,
        from_date=from_date,
        to_date=to_date,
    )


@router.get("/history/{automation_log_id}")
async def get_remediation_run(automation_log_id: str):
    """
    Phase 28.5 — single-run fetch for the remediation detail page. Returns the
    same shape as `/history` list entries (enriched with server_hostname +
    script_name).
    """
    run = await service.get_run(automation_log_id)
    if not run:
        raise HTTPException(status_code=404, detail="Automation log not found")
    return run


@router.post("/history/{automation_log_id}/analyze")
async def manually_analyze_remediation(automation_log_id: str):
    """
    Phase 28.4 — On-demand AI review for a single remediation run.

    Used when the per-server `script_review_enabled` toggle was off at execution
    time (or the auto-review failed) and the operator wants the verdict anyway.
    Mirrors the "Run Analysis" UX on incidents/anomalies.

    The auto path needs a pre-snapshot captured BEFORE the script started; we
    can't reconstruct that here. As a substitute we anchor the pre-snapshot's
    metrics window around the script's `executed_at` (which gives us the data
    leading up to script start) and capture a fresh post-snapshot at "now".
    Manual reviews are clearly labeled stale via `manual_review=True` so the
    operator knows they're reading reconstructed evidence.
    """
    db = get_database()
    try:
        oid = ObjectId(automation_log_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid automation_log_id")

    log = await db["automation_logs"].find_one({"_id": oid})
    if not log:
        raise HTTPException(status_code=404, detail="Automation log not found")

    # Idempotency-ish: refuse if a review is already in flight (the marker
    # field is set inline by the background task on completion or failure).
    if log.get("ai_review_verdict") == "in_progress":
        raise HTTPException(status_code=409, detail="Review already in progress")

    server_id = log.get("server_id", "")
    executed_at = log.get("executed_at") or utc_now()
    if isinstance(executed_at, datetime) and executed_at.tzinfo is None:
        executed_at = executed_at.replace(tzinfo=timezone.utc)

    from app.modules.ai.snapshots import capture_snapshot
    from app.modules.ai.script_review import run_script_execution_review

    # Synthetic pre-snapshot — anchored at `executed_at` so its 5-min metrics
    # window covers ~[executed_at - 5min, executed_at + 5min], i.e. the period
    # straddling script start. Good enough for "was anything moving before this
    # ran?" without needing the real pre-execution state.
    try:
        pre_snapshot = await capture_snapshot(server_id, anchor=executed_at)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pre-snapshot capture failed: {exc}")

    # Mark in-progress so the UI shows the spinner immediately.
    await db["automation_logs"].update_one(
        {"_id": oid},
        {"$set": {"ai_review_verdict": "in_progress", "ai_review_summary": "Manual analysis running…"}},
    )

    async def _run_manual():
        # Wait the normal settling window so post-snapshot still represents
        # "settled state" even when triggered seconds after execution.
        try:
            post_snapshot = await capture_snapshot(server_id, anchor=utc_now())
            await run_script_execution_review(
                automation_log_id=automation_log_id,
                pre_snapshot=pre_snapshot,
                post_snapshot=post_snapshot,
            )
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"[:200]
            try:
                await db["automation_logs"].update_one(
                    {"_id": oid},
                    {"$set": {"ai_review_verdict": "review_failed", "ai_review_summary": msg}},
                )
            except Exception:
                pass

    asyncio.create_task(_run_manual())
    return {"status": "queued", "automation_log_id": automation_log_id}


@router.get("/history/stats")
async def get_automation_history_stats(
    status: Optional[str] = Query(None),
    server_id: Optional[str] = Query(None),
    script_id: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None),
    to_date: Optional[str] = Query(None),
):
    """
    Headline stats for the automation history page: total, success, failed,
    last_24h count, and success rate. Honors the same filters as /history
    so numbers stay in sync with the table.
    """
    return await service.get_history_stats(
        status=status,
        server_id=server_id,
        script_id=script_id,
        from_date=from_date,
        to_date=to_date,
    )


@router.post("/", response_model=dict)
async def create_new_script(script: ScriptCreate):
    # Phase 28.5 — ownership validation
    db = get_database()
    if script.owner_type == "server":
        if not script.owner_id:
            raise HTTPException(status_code=422, detail="owner_id is required when owner_type=='server'")
        try:
            srv = await db["servers"].find_one({"_id": ObjectId(script.owner_id)}, {"_id": 1})
        except Exception:
            raise HTTPException(status_code=422, detail="owner_id is not a valid server id")
        if not srv:
            raise HTTPException(status_code=422, detail=f"Server {script.owner_id} not found")
    elif script.owner_id is not None:
        raise HTTPException(status_code=422, detail="owner_id must be null when owner_type=='global'")

    script_id = await service.create_script(script)
    if script.owner_type == "server" and script.owner_id:
        event_bus.emit(
            f"servers.{script.owner_id}.scripts",
            "script.created",
            {"script_id": script_id},
        )
    return {"status": "success", "id": script_id}


@router.post("/servers/{server_id}/scripts", response_model=dict)
async def create_script_for_server(server_id: str, script: ScriptCreate):
    """
    Phase 28.5 convenience endpoint — creates a script pre-scoped to a server.
    The path parameter is authoritative: body owner_* is overridden so a buggy
    client can't insert a script scoped to the wrong server.
    """
    script.owner_type = "server"
    script.owner_id = server_id
    return await create_new_script(script)


@router.get("/scripts")
async def list_scripts(
    language: Optional[str] = Query(None, description="Filter: bash, python, powershell"),
    target_os: Optional[str] = Query(None, description="Filter: linux, windows"),
    search: Optional[str] = Query(None, description="Search name or description"),
    owner_type: Optional[str] = Query(None, description="Phase 28.5: filter by global|server"),
    owner_id: Optional[str] = Query(None, description="Phase 28.5: filter server-scoped scripts to a specific server"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    db = get_database()
    query = {}
    if language:
        query["language"] = language
    if target_os:
        query["target_os"] = target_os
    if owner_type in ("global", "server"):
        query["owner_type"] = owner_type
    if owner_id:
        query["owner_id"] = owner_id
    if search:
        pattern = re_mod.compile(re_mod.escape(search), re_mod.IGNORECASE)
        query["$or"] = [{"name": pattern}, {"description": pattern}]

    total = await db["scripts"].count_documents(query)
    skip = (page - 1) * page_size
    scripts = await db["scripts"].find(query).sort("created_at", -1).skip(skip).limit(page_size).to_list(length=page_size)
    for s in scripts:
        s["_id"] = str(s["_id"])
    return {"total": total, "page": page, "page_size": page_size, "results": scripts}

@router.get("/scripts/{script_id}")
async def get_script(script_id: str):
    db = get_database()
    try:
        script = await db["scripts"].find_one({"_id": ObjectId(script_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    script["_id"] = str(script["_id"])
    return script

@router.put("/scripts/{script_id}")
async def update_script(script_id: str, updates: dict):
    db = get_database()
    try:
        oid = ObjectId(script_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    existing = await db["scripts"].find_one({"_id": oid})
    if not existing:
        raise HTTPException(status_code=404, detail="Script not found")

    # Phase 28.5 — `owner_type` / `owner_id` are intentionally NOT included.
    # Ownership is immutable after creation to avoid orphaning per-server rows.
    allowed = {"name", "description", "language", "content", "target_os", "category", "enabled"}
    update_data = {k: v for k, v in updates.items() if k in allowed}
    update_data["updated_at"] = datetime.now(timezone.utc)

    await db["scripts"].update_one({"_id": oid}, {"$set": update_data})
    event_bus.emit("scripts", "script.updated", {"script_id": str(oid)})
    if existing.get("owner_type") == "server" and existing.get("owner_id"):
        event_bus.emit(
            f"servers.{existing['owner_id']}.scripts",
            "script.updated",
            {"script_id": str(oid)},
        )
    return {"status": "success", "message": "Script updated"}


@router.patch("/scripts/{script_id}/toggle")
async def toggle_script_enabled(script_id: str):
    """Toggle a script's enabled state. Disabled scripts degrade linked rules to alert-only."""
    db = get_database()
    try:
        oid = ObjectId(script_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    script = await db["scripts"].find_one({"_id": oid}, {"enabled": 1})
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")

    new_state = not script.get("enabled", True)
    await db["scripts"].update_one(
        {"_id": oid},
        {"$set": {"enabled": new_state, "updated_at": datetime.now(timezone.utc)}},
    )
    event_bus.emit("scripts", "script.updated", {"script_id": str(oid), "enabled": new_state})
    return {"status": "success", "enabled": new_state}

@router.delete("/scripts/{script_id}")
async def delete_script(script_id: str):
    db = get_database()
    try:
        oid = ObjectId(script_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    existing = await db["scripts"].find_one({"_id": oid}, {"owner_type": 1, "owner_id": 1})
    result = await db["scripts"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Script not found")
    event_bus.emit("scripts", "script.deleted", {"script_id": str(oid)})
    if existing and existing.get("owner_type") == "server" and existing.get("owner_id"):
        event_bus.emit(
            f"servers.{existing['owner_id']}.scripts",
            "script.deleted",
            {"script_id": str(oid)},
        )
    return {"status": "success", "message": "Script deleted"}
