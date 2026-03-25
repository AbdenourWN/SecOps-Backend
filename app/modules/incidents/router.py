from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
from app.modules.incidents.service import IncidentService
from app.modules.incidents.schemas import IncidentResponse, IncidentStatusUpdate

router = APIRouter()
service = IncidentService()


@router.get("/stats")
async def get_incident_stats():
    """
    Dashboard aggregate: total count, breakdown by status and severity.
    NOTE: This route MUST be above /{incident_id} or FastAPI treats "stats" as an ID.
    """
    return await service.get_stats()


@router.get("/", response_model=List[IncidentResponse])
async def list_incidents(
    server_id: Optional[str] = Query(None, description="Filter by server"),
    severity: Optional[str] = Query(None, description="Filter: critical, high, medium, low"),
    status: Optional[str] = Query(None, description="Filter: open, investigating, resolved, false_positive"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List all incidents with optional filters. Sorted newest first.
    """
    return await service.get_all(
        server_id=server_id,
        severity=severity,
        status=status,
        skip=skip,
        limit=limit,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str):
    """
    Get a single incident by its ID.
    """
    incident = await service.get_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}/status")
async def update_incident_status(incident_id: str, body: IncidentStatusUpdate):
    """
    Update the status of an incident (resolve, investigate, mark as false positive).
    """
    result = await service.update_status(incident_id, body.status)

    if result.get("status") == "failed":
        if result.get("error") == "Incident not found":
            raise HTTPException(status_code=404, detail="Incident not found")
        raise HTTPException(status_code=400, detail=result.get("error"))

    return result
