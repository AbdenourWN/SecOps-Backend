import asyncio
import json
import logging
import re
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from app.core.config import settings
from app.core.events import event_bus
from app.core.ws_manager import connection_manager
from app.core.auth import ACCESS_COOKIE, authenticate_access_token

logger = logging.getLogger(__name__)


router = APIRouter()


ALLOWED_TOPICS: set[str] = {
    "incidents",
    "dashboard.summary",
    "servers.status",
    "automation.history",
    "servers",
    "log.sources",
    "rules",
    "scripts",
    # Phase 22 — Tier 2 heuristic anomalies
    "anomalies",
    # Phase 28.1 — AI actions global inbox (pending actions + commands)
    "ai_actions",
    # Phase 28.7 — app-wide AI overview stream (dashboard)
    "app.ai",
    # Phase 20.1 — in-app notifications are now per-recipient (`notifications.user.<id>`,
    # validated by _USER_NOTIF_TOPIC_RE); the old global `notifications` topic is gone.
    # Note: "servers.metrics" and "servers.logs" removed — replaced by
    # per-server topics validated by _SERVER_TOPIC_RE below.
}

# Matches per-server topics: "servers.<mongo-objectid>.<subtopic>" (group 1 = id).
# Phase 28.5: `rules` and `scripts` added so per-server library tabs refresh
# live when an operator (or AI approval) inserts a server-scoped row.
_SERVER_TOPIC_RE = re.compile(
    r"^servers\.([0-9a-f]{24})\.(metrics|logs|incidents|status|automation|anomalies|log_sources|ai|rules|scripts)$"
)
# Per-recipient in-app notification topic (Phase 20.1): notifications.user.<user-id>
_USER_NOTIF_TOPIC_RE = re.compile(r"^notifications\.user\.([0-9a-f]{24})$")


def _is_recognized_topic(topic: str) -> bool:
    return (
        topic in ALLOWED_TOPICS
        or bool(_SERVER_TOPIC_RE.match(topic))
        or bool(_USER_NOTIF_TOPIC_RE.match(topic))
    )


def _is_authorized_topic(topic: str, user) -> bool:
    """Per-principal subscribe-time RBAC. Flat (global) topics may be subscribed
    by any authenticated user, but their *delivery* is server-scoped per-recipient
    in `_bridge` (an event tagged with a server the user can't access is dropped),
    so a viewer can't observe cross-server activity. Per-server topics require
    access to that server; a user-notif topic must be the caller's own."""
    if topic in ALLOWED_TOPICS:
        return True
    m = _SERVER_TOPIC_RE.match(topic)
    if m:
        return user.can_access_server(m.group(1))
    m = _USER_NOTIF_TOPIC_RE.match(topic)
    if m:
        return m.group(1) == user.id
    return False


async def _bridge(ws: WebSocket, topic: str, user, queue: asyncio.Queue) -> None:
    """Drain one topic queue into the websocket. Exits silently on close.

    RBAC delivery filter (Phase 20.2): flat/global topics are open to every
    authenticated subscriber, so we enforce per-recipient server scope HERE — an
    event whose payload names a `server_id` the user can't access is dropped
    (admins pass everything; `can_access_server` is always True for them). Events
    without a `server_id` (global library CRUD, aggregate refetch triggers) pass
    through; the subsequent REST refetch is itself server-scoped, so no
    cross-server data is exposed. Per-server and per-user topics were already
    authorized at subscribe-time and are never filtered."""
    flat = topic in ALLOWED_TOPICS
    try:
        while True:
            msg = await queue.get()
            if flat:
                sid = (msg.get("payload") or {}).get("server_id")
                if sid and not user.can_access_server(sid):
                    continue  # cross-server event — not for this subscriber
            await ws.send_json(msg)
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        return
    except Exception as e:
        logger.warning("ws bridge error: %s", e)
        return


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    """
    App-wide realtime channel. One multiplexed socket per client.

    Client -> server: {type:"subscribe"|"unsubscribe"|"ping"|"auth", ...}
    Server -> client: {type:"event"|"subscribed"|"unsubscribed"|"pong"|"error", ...}
    """
    if not connection_manager.can_accept():
        # Try Again Later
        await ws.close(code=status.WS_1013_TRY_AGAIN_LATER)
        return

    # Authenticate from the access-token cookie before upgrading (Phase 20.1).
    user = await authenticate_access_token(ws.cookies.get(ACCESS_COOKIE))
    if user is None:
        await ws.close(code=4401)  # unauthenticated
        return

    await ws.accept()
    connection_manager.add(ws)

    # topic -> (queue, bridge_task)
    subs: dict[str, tuple[asyncio.Queue, asyncio.Task]] = {}

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({
                    "type": "error", "code": "invalid_json",
                    "message": "message must be JSON",
                })
                continue

            mtype = msg.get("type")

            if mtype == "ping":
                await ws.send_json({"type": "pong"})

            elif mtype == "auth":
                # Authentication already happened at connect via the cookie; this
                # frame is kept for protocol compatibility with existing clients.
                await ws.send_json({"type": "authed", "username": user.username})

            elif mtype == "subscribe":
                topic = msg.get("topic")
                if not _is_recognized_topic(topic):
                    await ws.send_json({
                        "type": "error", "code": "unknown_topic",
                        "message": f"unknown topic: {topic}",
                    })
                    continue
                if not _is_authorized_topic(topic, user):
                    await ws.send_json({
                        "type": "error", "code": "forbidden_topic",
                        "message": f"not authorized for topic: {topic}",
                    })
                    continue
                if topic in subs:
                    await ws.send_json({"type": "subscribed", "topic": topic})
                    continue
                q = event_bus.subscribe(topic, queue_size=settings.WS_MESSAGE_QUEUE_SIZE)
                task = asyncio.create_task(_bridge(ws, topic, user, q))
                subs[topic] = (q, task)
                await ws.send_json({"type": "subscribed", "topic": topic})

            elif mtype == "unsubscribe":
                topic = msg.get("topic")
                if topic in subs:
                    q, task = subs.pop(topic)
                    event_bus.unsubscribe(topic, q)
                    task.cancel()
                await ws.send_json({"type": "unsubscribed", "topic": topic})

            else:
                await ws.send_json({
                    "type": "error", "code": "unknown_type",
                    "message": f"unknown message type: {mtype!r}",
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("ws endpoint error: %s", e)
    finally:
        for topic, (q, task) in list(subs.items()):
            event_bus.unsubscribe(topic, q)
            task.cancel()
        connection_manager.remove(ws)
