"""
REST surface for the in-app notification feed (Phase 29; scoped in Phase 20.1).

Mounted under the same `/api/notifications` prefix as the email/LLM config
router, but scoped to `/feed*` paths so the two never collide. The feed is the
access-control boundary — every method runs through `_scope_query(principal)`
so each user only sees / mutates their own + their servers' + app-wide rows.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.core.auth import CurrentUser, get_current_user
from app.core.errors import http_error
from app.modules.notifications.feed import NotificationFeedService
from app.modules.notifications.feed_schemas import NotificationListResponse

router = APIRouter()


# Static routes first so they aren't shadowed by `/feed/{notification_id}/read`.
@router.get("/feed", response_model=NotificationListResponse)
async def list_notifications(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    unread_only: bool = False,
    category: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    user: CurrentUser = Depends(get_current_user),
):
    """Paginated, newest-first feed page. Filters: unread / category / date range."""
    try:
        return await NotificationFeedService().list_page(
            page=page,
            page_size=page_size,
            unread_only=unread_only,
            category=category,
            from_date=from_date,
            to_date=to_date,
            principal=user,
        )
    except Exception as exc:
        raise http_error(500, "Couldn't load notifications.", exc, "list notifications")


@router.get("/feed/unread-count")
async def unread_count(user: CurrentUser = Depends(get_current_user)):
    """Unread badge count."""
    try:
        return {"count": await NotificationFeedService().unread_count(principal=user)}
    except Exception as exc:
        raise http_error(500, "Couldn't load the notification count.", exc, "unread count")


@router.post("/feed/read-all")
async def mark_all_read(user: CurrentUser = Depends(get_current_user)):
    """Mark every (visible) unread notification read."""
    try:
        return {"updated": await NotificationFeedService().mark_all_read(principal=user)}
    except Exception as exc:
        raise http_error(500, "Couldn't update notifications.", exc, "mark all read")


@router.post("/feed/{notification_id}/read")
async def mark_read(notification_id: str, user: CurrentUser = Depends(get_current_user)):
    """Mark one notification read (called on row click before navigation)."""
    return {"updated": await NotificationFeedService().mark_read(notification_id, principal=user)}


@router.delete("/feed/{notification_id}")
async def dismiss(notification_id: str, user: CurrentUser = Depends(get_current_user)):
    """Remove a notification from the feed."""
    return {"deleted": await NotificationFeedService().dismiss(notification_id, principal=user)}
