from fastapi import APIRouter, HTTPException
from typing import List
from app.modules.logs.service import LogService
from app.modules.logs.schemas import LogResponse

router = APIRouter()
service = LogService()

@router.post("/collect/{server_id}")
async def trigger_log_collection(server_id: str):
    """
    Manually triggers log collection.
    Useful for testing before we build the Scheduler.
    """
    result = await service.collect_logs_from_server(server_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.get("/{server_id}", response_model=List[LogResponse])
async def get_server_logs(server_id: str, limit: int = 50):
    """
    Fetch the latest logs from the database.
    """
    return await service.get_logs(server_id, limit)