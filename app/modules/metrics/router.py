from fastapi import APIRouter
from typing import List
from app.modules.metrics.service import MetricService
from app.modules.metrics.schemas import MetricResponse

router = APIRouter()
service = MetricService()

@router.post("/collect/{server_id}")
async def trigger_collection(server_id: str):
    success = await service.collect_metrics(server_id)
    return {"status": "success" if success else "failed"}

@router.get("/{server_id}", response_model=List[MetricResponse])
async def get_metrics(server_id: str, limit: int = 20):
    return await service.get_latest_metrics(server_id, limit)