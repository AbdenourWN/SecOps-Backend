from fastapi import APIRouter, Query
from app.modules.dashboard.service import DashboardService

router = APIRouter()
service = DashboardService()


@router.get("/summary")
async def get_dashboard_summary():
    """
    Full dashboard overview: server counts, incident stats,
    log volume, active rules, and available scripts.
    """
    return await service.get_summary()


@router.get("/recent-incidents")
async def get_recent_incidents(limit: int = Query(10, ge=1, le=50)):
    """
    Latest incidents for the dashboard feed.
    Enriched with server hostname.
    """
    return await service.get_recent_incidents(limit)


@router.get("/server-health")
async def get_server_health():
    """
    All servers with their latest metric snapshot
    and open incident count.
    """
    return await service.get_server_health()
