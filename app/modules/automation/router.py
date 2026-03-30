from fastapi import APIRouter, HTTPException
from app.modules.automation.schemas import ScriptCreate, ScriptInDB
from app.modules.automation.service import AutomationService
from app.core.database import get_database
from bson import ObjectId
from datetime import datetime, timezone

router = APIRouter()
service = AutomationService()

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
