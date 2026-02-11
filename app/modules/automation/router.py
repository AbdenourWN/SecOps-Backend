from fastapi import APIRouter
from app.modules.automation.schemas import ScriptCreate, ScriptInDB
from app.modules.automation.service import AutomationService

router = APIRouter()
service = AutomationService()

@router.post("/", response_model=dict)
async def create_new_script(script: ScriptCreate):
    script_id = await service.create_script(script)
    return {"status": "success", "id": script_id}