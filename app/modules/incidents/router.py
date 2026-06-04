from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List
from pydantic import BaseModel
from app.modules.incidents.service import IncidentService
from app.modules.incidents.schemas import IncidentResponse, IncidentStatusUpdate
from app.core.auth import CurrentUser, ensure_server_access, get_current_user, require_role
from app.core.constants import UserRole

router = APIRouter()
service = IncidentService()
_operator = require_role(UserRole.OPERATOR.value)


class IncidentListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[IncidentResponse]


@router.get("/stats")
async def get_incident_stats(user: CurrentUser = Depends(get_current_user)):
    """
    Dashboard aggregate: total count, breakdown by status and severity.
    Scoped to the principal's servers (admins see all).
    NOTE: This route MUST be above /{incident_id} or FastAPI treats "stats" as an ID.
    """
    return await service.get_stats(allowed_server_ids=None if user.is_admin else user.server_ids)


@router.get("/", response_model=IncidentListResponse)
async def list_incidents(
    server_id: Optional[str] = Query(None, description="Filter by server"),
    severity: Optional[str] = Query(None, description="Filter: critical, high, medium, low"),
    status: Optional[str] = Query(None, description="Filter: open, investigating, resolved, false_positive"),
    search: Optional[str] = Query(None, description="Search in description and rule_id"),
    from_date: Optional[str] = Query(None, description="ISO datetime — only incidents detected at/after this time"),
    to_date: Optional[str] = Query(None, description="ISO datetime — only incidents detected at/before this time"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    user: CurrentUser = Depends(get_current_user),
):
    """
    List all incidents with optional filters. Sorted newest first.
    Date filters apply on `detected_at`. Scoped to the principal's servers.
    """
    return await service.get_all(
        server_id=server_id,
        severity=severity,
        status=status,
        search=search,
        from_date=from_date,
        to_date=to_date,
        page=page,
        page_size=page_size,
        allowed_server_ids=None if user.is_admin else user.server_ids,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, user: CurrentUser = Depends(get_current_user)):
    """
    Get a single incident by its ID.
    """
    incident = await service.get_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_server_access(user, str(incident.get("server_id")))
    return incident


@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    body: IncidentStatusUpdate,
    user: CurrentUser = Depends(_operator),
):
    """
    Update the status of an incident (resolve, investigate, mark as false positive).
    """
    existing = await service.get_by_id(incident_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_server_access(user, str(existing.get("server_id")))
    result = await service.update_status(incident_id, body.status)

    if result.get("status") == "failed":
        if result.get("error") == "Incident not found":
            raise HTTPException(status_code=404, detail="Incident not found")
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result
