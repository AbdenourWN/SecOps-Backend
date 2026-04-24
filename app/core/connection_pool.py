"""
Per-server connection pool for SSH (Paramiko) and WinRM sessions.

Design rules:
- One PoolEntry per server_id. Each entry holds a live executor + asyncio.Lock.
- The lock serializes ALL access to a server (scheduler + terminals share it).
- Scheduler uses try_get(timeout) → skips the tick if the server is busy.
- Terminals use get() → wait until the lock is available.
- Credential freshness check runs on every get/try_get (1 small DB query).
- Liveness probe runs if connection was idle >10 s.
- Background sweeper closes idle connections (>5 min).
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId

from app.core.database import get_database
from app.core.executors import BaseExecutor, get_server_executor
from app.core.security import decrypt_password

logger = logging.getLogger(__name__)

_IDLE_TTL_S = 300        # evict connections idle for >5 min
_SWEEP_INTERVAL_S = 60   # sweeper wakes every 1 min
_STALL_THRESHOLD = 3     # consecutive skips before "stalled" event


@dataclass
class PoolEntry:
    executor: BaseExecutor
    lock: asyncio.Lock
    credential_id: str          # snapshot at entry creation
    last_used_at: float = 0.0   # loop.time() of last successful use
    consecutive_skip_count: int = 0


class ConnectionPool:
    def __init__(self) -> None:
        self._pool: dict[str, PoolEntry] = {}
        self._sweeper: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._sweeper = asyncio.create_task(self._sweep_loop())
        logger.info("[pool] started (idle_ttl=%ds, sweep=%ds)", _IDLE_TTL_S, _SWEEP_INTERVAL_S)

    async def close_all(self, grace_s: float = 5.0) -> None:
        if self._sweeper:
            self._sweeper.cancel()
            try:
                await self._sweeper
            except asyncio.CancelledError:
                pass
        entries = list(self._pool.values())
        self._pool.clear()
        close_tasks = [asyncio.create_task(e.executor.close()) for e in entries]
        if close_tasks:
            done, pending = await asyncio.wait(close_tasks, timeout=grace_s)
            for t in pending:
                t.cancel()
        logger.info("[pool] closed all connections")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def get(self, server_id: str):
        """Acquire a live executor. Blocks until the per-server lock is available."""
        entry = await self._get_or_create(server_id)
        async with entry.lock:
            await entry.executor._ensure_connected()
            entry.last_used_at = asyncio.get_event_loop().time()
            entry.consecutive_skip_count = 0
            yield entry.executor

    @asynccontextmanager
    async def try_get(self, server_id: str, timeout: float = 5.0):
        """
        Acquire a live executor or yield None if the lock is busy.
        Used by scheduler jobs so they skip rather than pile up.
        """
        entry = await self._get_or_create(server_id)
        acquired = False
        try:
            await asyncio.wait_for(entry.lock.acquire(), timeout=timeout)
            acquired = True
        except asyncio.TimeoutError:
            entry.consecutive_skip_count += 1
            yield None
            return

        try:
            await entry.executor._ensure_connected()
            entry.last_used_at = asyncio.get_event_loop().time()
            entry.consecutive_skip_count = 0
            yield entry.executor
        finally:
            entry.lock.release()

    def evict(self, server_id: str) -> None:
        """
        Remove and close a pool entry. Call on server delete or credential change.
        Fire-and-forget — the close is scheduled as a background task.
        """
        entry = self._pool.pop(server_id, None)
        if entry:
            asyncio.create_task(entry.executor.close())
            logger.info("[pool] evicted %s", server_id)

    def get_skip_count(self, server_id: str) -> int:
        entry = self._pool.get(server_id)
        return entry.consecutive_skip_count if entry else 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_or_create(self, server_id: str) -> PoolEntry:
        # Credential-freshness check on every access (1 tiny DB projection)
        if server_id in self._pool:
            if await self._credential_changed(server_id, self._pool[server_id]):
                logger.info("[pool] credential changed for %s — evicting", server_id)
                self.evict(server_id)

        if server_id not in self._pool:
            entry = await self._create_entry(server_id)
            self._pool[server_id] = entry
        return self._pool[server_id]

    async def _credential_changed(self, server_id: str, entry: PoolEntry) -> bool:
        """
        Returns True if the server has been re-linked to a different credential.
        Relies on explicit evict() for same-credential password changes.
        """
        db = get_database()
        try:
            server = await db["servers"].find_one(
                {"_id": ObjectId(server_id)},
                projection={"credential_id": 1},
            )
        except Exception:
            return False
        if not server:
            return True  # server was deleted
        return str(server.get("credential_id", "")) != entry.credential_id

    async def _create_entry(self, server_id: str) -> PoolEntry:
        db = get_database()
        try:
            s_oid = ObjectId(server_id)
        except Exception:
            raise ValueError(f"Invalid server ID: {server_id}")

        server = await db["servers"].find_one({"_id": s_oid})
        if not server:
            raise ValueError(f"Server not found: {server_id}")

        cred = await db["credentials"].find_one({"_id": ObjectId(server["credential_id"])})
        if not cred:
            raise ValueError(f"Credential not found for server: {server_id}")

        plain_secret = decrypt_password(cred["encrypted_secret"])
        executor = get_server_executor(server, plain_password=plain_secret)
        executor.credential["username"] = cred["username"]

        logger.info("[pool] created entry for %s (%s)", server.get("hostname"), server_id)
        return PoolEntry(
            executor=executor,
            lock=asyncio.Lock(),
            credential_id=str(cred["_id"]),
        )

    async def _sweep_loop(self) -> None:
        while True:
            await asyncio.sleep(_SWEEP_INTERVAL_S)
            now = asyncio.get_event_loop().time()
            idle = [
                sid for sid, e in list(self._pool.items())
                if (now - e.last_used_at) > _IDLE_TTL_S
            ]
            for sid in idle:
                logger.info("[pool] sweeper: evicting idle connection %s", sid)
                self.evict(sid)


# Module-level singleton used by scheduler + service layer
connection_pool = ConnectionPool()
