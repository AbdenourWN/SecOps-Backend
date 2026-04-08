from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.modules.automation.schemas import ScriptCreate, ScriptInDB
from app.modules.automation.service import AutomationService
from app.core.database import get_database
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
):
    """
    Remediation runs (newest first), enriched with server hostname + script name.
    Supports pagination and status/server/script filters — used by both the
    dashboard activity widget and the dedicated automation history page.
    NOTE: Must be declared above /{script_id}-style routes.
    """
    return await service.get_history(
        limit=limit,
        skip=skip,
        status=status,
        server_id=server_id,
        script_id=script_id,
    )


@router.get("/history/stats")
async def get_automation_history_stats(
    status: Optional[str] = Query(None),
    server_id: Optional[str] = Query(None),
    script_id: Optional[str] = Query(None),
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
    )


@router.post("/", response_model=dict)
async def create_new_script(script: ScriptCreate):
    script_id = await service.create_script(script)
    return {"status": "success", "id": script_id}

@router.get("/scripts", response_model=list)
async def list_scripts():
    db = get_database()
    scripts = await db["scripts"].find().to_list(length=100)
    for s in scripts:
        s["_id"] = str(s["_id"])
    return scripts

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

    allowed = {"name", "description", "language", "content", "target_os"}
    update_data = {k: v for k, v in updates.items() if k in allowed}
    update_data["updated_at"] = datetime.now(timezone.utc)

    await db["scripts"].update_one({"_id": oid}, {"$set": update_data})
    return {"status": "success", "message": "Script updated"}

@router.delete("/scripts/{script_id}")
async def delete_script(script_id: str):
    db = get_database()
    try:
        oid = ObjectId(script_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    result = await db["scripts"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Script not found")
    return {"status": "success", "message": "Script deleted"}
