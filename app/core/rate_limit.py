"""
In-memory sliding-window rate limiter.

Keyed by (principal, server_id). 30 commands per 60 seconds by default.
Thread-safe via asyncio.Lock. Swap to Redis later without changing callers.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from time import monotonic
from typing import Deque, Dict, Tuple


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after_s: int = 0


DEFAULT_WINDOW_SECONDS = 60
DEFAULT_MAX_HITS = 30


class _SlidingWindow:
    def __init__(self, window_s: int, max_hits: int) -> None:
        self.window_s = window_s
        self.max_hits = max_hits
        self._buckets: Dict[Tuple[str, str], Deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, principal: str, server_id: str) -> RateLimitResult:
        now = monotonic()
        cutoff = now - self.window_s
        key = (principal, server_id)

        async with self._lock:
            q = self._buckets.get(key)
            if q is None:
                q = deque()
                self._buckets[key] = q

            while q and q[0] < cutoff:
                q.popleft()

            if len(q) >= self.max_hits:
                oldest = q[0]
                retry_after = int(self.window_s - (now - oldest)) + 1
                return RateLimitResult(allowed=False, retry_after_s=max(1, retry_after))

            q.append(now)
            return RateLimitResult(allowed=True)


_default = _SlidingWindow(DEFAULT_WINDOW_SECONDS, DEFAULT_MAX_HITS)


async def check_rate_limit(principal: str, server_id: str) -> RateLimitResult:
    return await _default.check(principal, server_id)
