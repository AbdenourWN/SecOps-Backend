import asyncio
import json
import re
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from app.core.config import settings
from app.core.events import event_bus
from app.core.ws_manager import connection_manager


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
    # Note: "servers.metrics" and "servers.logs" removed — replaced by
    # per-server topics validated by _SERVER_TOPIC_RE below.
}

# Matches per-server topics: "servers.<mongo-objectid>.<subtopic>"
_SERVER_TOPIC_RE = re.compile(
    r"^servers\.[0-9a-f]{24}\.(metrics|logs|incidents|status|automation|anomalies|log_sources|ai)$"
)


def _is_allowed_topic(topic: str) -> bool:
    return topic in ALLOWED_TOPICS or bool(_SERVER_TOPIC_RE.match(topic))


async def _bridge(ws: WebSocket, queue: asyncio.Queue) -> None:
    """Drain one topic queue into the websocket. Exits silently on close."""
    try:
        while True:
            msg = await queue.get()
            await ws.send_json(msg)
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        return
    except Exception as e:
        print(f"⚠️  ws bridge error: {e}")
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
                # Stub: accepts any/no token. Real JWT validation lands with P4.1.
                await ws.send_json({"type": "authed"})

            elif mtype == "subscribe":
                topic = msg.get("topic")
                if not _is_allowed_topic(topic):
                    await ws.send_json({
                        "type": "error", "code": "unknown_topic",
                        "message": f"unknown topic: {topic}",
                    })
                    continue
                if topic in subs:
                    await ws.send_json({"type": "subscribed", "topic": topic})
                    continue
                q = event_bus.subscribe(topic, queue_size=settings.WS_MESSAGE_QUEUE_SIZE)
                task = asyncio.create_task(_bridge(ws, q))
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
        print(f"⚠️  ws endpoint error: {e}")
    finally:
        for topic, (q, task) in list(subs.items()):
            event_bus.unsubscribe(topic, q)
            task.cancel()
        connection_manager.remove(ws)
