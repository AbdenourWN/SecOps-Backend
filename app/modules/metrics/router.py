from fastapi import APIRouter, Depends
from typing import List, Optional
from app.modules.metrics.service import MetricService
from app.modules.metrics.schemas import MetricResponse
from app.core.auth import CurrentUser, ensure_server_access, get_current_user, require_role
from app.core.constants import UserRole

router = APIRouter()
service = MetricService()
_operator = require_role(UserRole.OPERATOR.value)

@router.post("/collect/{server_id}")
async def trigger_collection(server_id: str, user: CurrentUser = Depends(_operator)):
    ensure_server_access(user, server_id)
    success = await service.collect_metrics(server_id)
    return {"status": "success" if success else "failed"}

@router.get("/{server_id}", response_model=List[MetricResponse])
async def get_metrics(
    server_id: str,
    limit: int = 100,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    user: CurrentUser = Depends(get_current_user),
):
    ensure_server_access(user, server_id)
    return await service.get_latest_metrics(server_id, limit, from_date, to_date)