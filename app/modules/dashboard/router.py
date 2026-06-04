import asyncio
from fastapi import APIRouter, Query, Depends
from app.modules.dashboard.service import DashboardService
from app.core.auth import CurrentUser, get_current_user, require_role
from app.core.constants import UserRole

router = APIRouter()
service = DashboardService()
_admin = require_role(UserRole.ADMIN.value)


def _scope(user: CurrentUser):
    return None if user.is_admin else user.server_ids


@router.get("/summary")
async def get_dashboard_summary(user: CurrentUser = Depends(get_current_user)):
    """
    Full dashboard overview: server counts, incident stats,
    log volume, active rules, and available scripts. Scoped to the principal's servers.
    """
    return await service.get_summary(allowed_server_ids=_scope(user))


@router.get("/recent-incidents")
async def get_recent_incidents(limit: int = Query(10, ge=1, le=50), user: CurrentUser = Depends(get_current_user)):
    """
    Latest incidents for the dashboard feed.
    Enriched with server hostname. Scoped to the principal's servers.
    """
    return await service.get_recent_incidents(limit, allowed_server_ids=_scope(user))


@router.get("/server-health")
async def get_server_health(user: CurrentUser = Depends(get_current_user)):
    """
    All servers with their latest metric snapshot
    and open incident count. Scoped to the principal's servers.
    """
    return await service.get_server_health(allowed_server_ids=_scope(user))


@router.get("/ai-overview")
async def get_ai_overview(user: CurrentUser = Depends(_admin)):
    """
    Latest persisted app-wide AI overview (or null if none generated yet).
    Pure DB read — never triggers an LLM call. Generation is on-demand via POST.
    Admin-only: the overview summarises the whole platform across all servers.
    """
    from app.modules.ai.app_overview import get_latest_app_overview
    return await get_latest_app_overview()


@router.post("/ai-overview")
async def generate_ai_overview(user: CurrentUser = Depends(_admin)):
    """
    Kick off a fresh app-wide AI overview. Fire-and-forget: streams tokens on
    the `app.ai` WS topic and persists the result. Returns immediately so the
    frontend can subscribe and watch the live typing. Admin-only (app-wide).
    """
    from app.modules.ai.app_overview import run_app_overview
    asyncio.create_task(run_app_overview())
    return {"status": "queued"}
