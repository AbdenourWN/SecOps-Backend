import asyncio
from typing import Any


class EventBus:
    """
    In-process pub/sub for real-time app events.

    Services emit; websocket bridge tasks subscribe. Emit is synchronous and
    non-blocking (put_nowait): a slow or stalled subscriber drops its own
    messages rather than blocking the mutating service coroutine.

    Swap-door: replace put_nowait with Redis pub/sub when we multi-worker.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = {}

    def subscribe(self, topic: str, queue_size: int = 64) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._subscribers.setdefault(topic, set()).add(q)
        return q

    def unsubscribe(self, topic: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(topic)
        if not subs:
            return
        subs.discard(queue)
        if not subs:
            self._subscribers.pop(topic, None)

    def emit(self, topic: str, event: str, payload: dict[str, Any]) -> None:
        subs = self._subscribers.get(topic)
        if not subs:
            return
        message = {"type": "event", "topic": topic, "event": event, "payload": payload}
        for q in list(subs):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                # Slow subscriber: drop this message for them, keep others moving.
                pass

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, ()))


event_bus = EventBus()
