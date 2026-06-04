"""
In-app notification feed (Phase 29).

Persistent, DB-backed notifications shown in the header bell + the
`/notifications` page. This is a separate concern from `service.py` (outbound
email/SMTP alert config): that module *sends* alerts, this one records the
*inbound* feed the operator reads.

`notify(...)` is the single entry point services call at lifecycle points (AI
analysis finished, incident created, remediation outcome, …). It is
**best-effort**: any failure is swallowed so a notification never breaks the
emitting flow.

RBAC (Phase 20.1): every row stores `server_id` + `user_id` (None = all admins).
`_scope_query(principal)` filters the REST feed to the principal's own + their
servers' + app-wide rows, and `_emit` fans each notification out to per-recipient
WS topics (`notifications.user.<id>`) resolved from the row's scope.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.core.constants import (
    Collections,
    NotificationCategory,
    NotificationSeverity,
    NotificationType,
    UserRole,
    user_notif_topic,
)
from app.core.database import get_database
from app.core.db_utils import build_date_range_query, safe_object_id
from app.core.events import event_bus

logger = logging.getLogger(__name__)


def _val(v) -> Optional[str]:
    """Accept an enum member or a raw string; store the plain string value."""
    if v is None:
        return None
    return v.value if isinstance(v, (NotificationType, NotificationCategory, NotificationSeverity)) else str(v)


def _serialize(doc: dict) -> dict:
    """
    Mongo doc → API/WS shape: `_id` → string `id`, and **all datetimes → ISO
    strings**. The ISO conversion is critical for the WebSocket path: the WS
    bridge sends via `ws.send_json` (plain `json.dumps`, no datetime encoder),
    so a raw `datetime` in the payload would raise and silently kill that
    client's topic stream. ISO strings are also exactly what the frontend type
    (`AppNotification.created_at: string`) expects.
    """
    out = {
        k: (v.isoformat() if isinstance(v, datetime) else v)
        for k, v in doc.items()
    }
    out["id"] = str(out.pop("_id"))
    return out


class NotificationFeedService:
    @property
    def _col(self):
        return get_database()[Collections.NOTIFICATIONS]

    # ── write ──────────────────────────────────────────────────────────────
    async def create(
        self,
        *,
        type,
        title: str,
        category,
        severity=NotificationSeverity.INFO,
        link: Optional[str] = None,
        body: Optional[str] = None,
        server_id: Optional[str] = None,
        user_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        dedup_key: Optional[str] = None,
        dedup_window_s: Optional[int] = None,
    ) -> dict:
        col = self._col
        now = datetime.now(timezone.utc)

        # Dedup-coalesce: bump an existing UNREAD row with the same key inside
        # the window instead of inserting a near-duplicate (repeat anomalies,
        # health flaps). Keeps signal (count++) without spamming the feed.
        if dedup_key and dedup_window_s:
            since = now - timedelta(seconds=dedup_window_s)
            existing = await col.find_one(
                {"dedup_key": dedup_key, "read": False, "created_at": {"$gte": since}},
                sort=[("_id", -1)],
            )
            if existing:
                await col.update_one(
                    {"_id": existing["_id"]},
                    {
                        "$inc": {"count": 1},
                        "$set": {"updated_at": now, "title": title, "body": body},
                    },
                )
                merged = {
                    **existing,
                    "count": existing.get("count", 1) + 1,
                    "updated_at": now,
                    "title": title,
                    "body": body,
                }
                out = _serialize(merged)
                recipients = await self._resolve_recipients(merged.get("server_id"), merged.get("user_id"))
                self._emit(out, recipients)
                return out

        doc = {
            "type": _val(type),
            "category": _val(category),
            "severity": _val(severity),
            "title": title,
            "body": body,
            "link": link,
            "server_id": server_id,
            "user_id": user_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "dedup_key": dedup_key,
            "read": False,
            "read_at": None,
            "count": 1,
            "created_at": now,
            "updated_at": now,
        }
        result = await col.insert_one(doc)
        doc["_id"] = result.inserted_id
        out = _serialize(doc)
        recipients = await self._resolve_recipients(server_id, user_id)
        self._emit(out, recipients)
        return out

    async def _resolve_recipients(self, server_id: Optional[str], user_id: Optional[str]) -> list[str]:
        """Which user ids receive this notification: a specific `user_id`; else
        all users assigned to `server_id` plus all admins; else (app-wide) all
        admins. Admins always see server-scoped + app-wide notifications."""
        users = get_database()[Collections.USERS]
        if user_id:
            return [user_id]
        admin_ids = [
            str(u["_id"])
            async for u in users.find({"role": UserRole.ADMIN.value, "is_active": True}, {"_id": 1})
        ]
        if server_id:
            assigned = [
                str(u["_id"])
                async for u in users.find({"server_ids": server_id, "is_active": True}, {"_id": 1})
            ]
            return list({*admin_ids, *assigned})
        return admin_ids

    def _emit(self, out: dict, recipient_ids: list[str]) -> None:
        """Fan the notification to each recipient's per-user topic (Phase 20.1)."""
        for uid in recipient_ids:
            try:
                event_bus.emit(user_notif_topic(uid), "notification.created", out)
            except Exception:
                pass

    # ── read / mutate ────────────────────────────────────────────────────────
    def _scope_query(self, principal=None) -> dict:
        """Per-principal access filter (Phase 20.1). Admin — or no principal (an
        internal caller) — sees everything; otherwise the principal sees their own
        rows + rows scoped to an assigned server + app-wide rows."""
        if principal is None or getattr(principal, "is_admin", False):
            return {}
        return {
            "$or": [
                {"user_id": principal.id},
                {"user_id": None, "server_id": {"$in": principal.server_ids}},
                {"user_id": None, "server_id": None},
            ]
        }

    async def list_page(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        unread_only: bool = False,
        category: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        principal=None,
    ) -> dict:
        """Paginated, newest-first feed page. Filters: unread / category / date range."""
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        query = self._scope_query(principal)
        if unread_only:
            query["read"] = False
        if category:
            query["category"] = _val(category)
        rng = build_date_range_query(from_date, to_date)
        if rng:
            query["created_at"] = rng
        total = await self._col.count_documents(query)
        cursor = (
            self._col.find(query)
            .sort("_id", -1)
            .skip((page - 1) * page_size)
            .limit(page_size)
        )
        docs = await cursor.to_list(length=page_size)
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "results": [_serialize(d) for d in docs],
        }

    async def unread_count(self, *, principal=None) -> int:
        query = self._scope_query(principal)
        query["read"] = False
        return await self._col.count_documents(query)

    async def mark_read(self, notification_id: str, *, principal=None) -> bool:
        oid = safe_object_id(notification_id)
        if oid is None:
            return False
        query = self._scope_query(principal)  # scope so a user can't touch others' rows
        query["_id"] = oid
        query["read"] = False
        res = await self._col.update_one(
            query,
            {"$set": {"read": True, "read_at": datetime.now(timezone.utc)}},
        )
        return res.modified_count > 0

    async def mark_all_read(self, *, principal=None) -> int:
        query = self._scope_query(principal)
        query["read"] = False
        res = await self._col.update_many(
            query, {"$set": {"read": True, "read_at": datetime.now(timezone.utc)}}
        )
        return res.modified_count

    async def dismiss(self, notification_id: str, *, principal=None) -> bool:
        oid = safe_object_id(notification_id)
        if oid is None:
            return False
        query = self._scope_query(principal)  # scope so a user can't delete others' rows
        query["_id"] = oid
        res = await self._col.delete_one(query)
        return res.deleted_count > 0


async def notify(
    *,
    type,
    title: str,
    category,
    severity=NotificationSeverity.INFO,
    link: Optional[str] = None,
    body: Optional[str] = None,
    server_id: Optional[str] = None,
    user_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    dedup_key: Optional[str] = None,
    dedup_window_s: Optional[int] = None,
) -> Optional[dict]:
    """
    Record + fan out an in-app notification. Best-effort: never raises — a
    notification failure must not break the flow that emitted it.
    """
    try:
        return await NotificationFeedService().create(
            type=type,
            title=title,
            category=category,
            severity=severity,
            link=link,
            body=body,
            server_id=server_id,
            user_id=user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            dedup_key=dedup_key,
            dedup_window_s=dedup_window_s,
        )
    except Exception:
        try:
            logger.exception("notify failed type=%s", _val(type))
        except Exception:
            pass
        return None
