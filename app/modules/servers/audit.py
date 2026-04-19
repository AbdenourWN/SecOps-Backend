"""
Command audit log. Every /execute attempt — success, block, timeout,
rate-limit, error — writes one row to `command_audit`. Full output is never
persisted; previews are truncated to 4 KB per stream.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pymongo import ASCENDING, DESCENDING

from app.core.database import get_database


AuditStatus = Literal[
    "ok",
    "error",
    "timeout",
    "blocked",
    "requires_confirmation",
    "rate_limited",
]


PREVIEW_MAX_BYTES = 4096
# 90 days in seconds — MongoDB TTL expires docs based on `started_at`.
AUDIT_TTL_SECONDS = 60 * 60 * 24 * 90


def _preview(text: str | None) -> tuple[str, int]:
    if not text:
        return "", 0
    raw = text.encode("utf-8", errors="replace")
    total = len(raw)
    if total <= PREVIEW_MAX_BYTES:
        return text, total
    return raw[:PREVIEW_MAX_BYTES].decode("utf-8", errors="replace") + "…[truncated]", total


async def ensure_audit_indexes() -> None:
    """Call once at startup. Idempotent."""
    db = get_database()
    await db["command_audit"].create_index(
        [("started_at", ASCENDING)], expireAfterSeconds=AUDIT_TTL_SECONDS
    )
    await db["command_audit"].create_index(
        [("server_id", ASCENDING), ("started_at", DESCENDING)]
    )
    await db["command_audit"].create_index(
        [("principal_id", ASCENDING), ("started_at", DESCENDING)]
    )


async def write_audit(
    *,
    server_id: str,
    command: str,
    status: AuditStatus,
    started_at: datetime,
    finished_at: Optional[datetime] = None,
    principal_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    exit_code: Optional[int] = None,
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
    blocked_reason: Optional[str] = None,
    confirmed: bool = False,
) -> None:
    finished = finished_at or datetime.now(timezone.utc)
    stdout_preview, stdout_bytes = _preview(stdout)
    stderr_preview, stderr_bytes = _preview(stderr)

    duration_ms = int((finished - started_at).total_seconds() * 1000)

    doc = {
        "principal_id": principal_id,
        "source_ip": source_ip,
        "server_id": server_id,
        "command": command,
        "started_at": started_at,
        "finished_at": finished,
        "duration_ms": max(0, duration_ms),
        "exit_code": exit_code,
        "status": status,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "blocked_reason": blocked_reason,
        "confirmed": confirmed,
    }
    try:
        await get_database()["command_audit"].insert_one(doc)
    except Exception as e:
        # Audit must never break the user-facing call. Log and move on.
        print(f"⚠️  audit write failed: {e}")
