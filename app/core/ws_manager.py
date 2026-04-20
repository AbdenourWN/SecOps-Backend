from fastapi import WebSocket
from app.core.config import settings


class ConnectionManager:
    """
    Tracks live websocket connections for the app-wide realtime channel.
    Enforces a global cap; per-connection topic state lives in the router.
    """

    def __init__(self) -> None:
        self.active: set[WebSocket] = set()

    def can_accept(self) -> bool:
        return len(self.active) < settings.WS_MAX_CONNECTIONS

    def add(self, ws: WebSocket) -> None:
        self.active.add(ws)

    def remove(self, ws: WebSocket) -> None:
        self.active.discard(ws)

    def count(self) -> int:
        return len(self.active)


connection_manager = ConnectionManager()
