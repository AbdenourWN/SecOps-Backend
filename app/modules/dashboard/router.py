import asyncio
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


@router.get("/ai-overview")
async def get_ai_overview():
    """
    Latest persisted app-wide AI overview (or null if none generated yet).
    Pure DB read — never triggers an LLM call. Generation is on-demand via POST.
    """
    from app.modules.ai.app_overview import get_latest_app_overview
    return await get_latest_app_overview()


@router.post("/ai-overview")
async def generate_ai_overview():
    """
    Kick off a fresh app-wide AI overview. Fire-and-forget: streams tokens on
    the `app.ai` WS topic and persists the result. Returns immediately so the
    frontend can subscribe and watch the live typing.
    """
    from app.modules.ai.app_overview import run_app_overview
    asyncio.create_task(run_app_overview())
    return {"status": "queued"}
