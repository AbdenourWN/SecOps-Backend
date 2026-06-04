"""
Auth core (Phase 20.1) — JWT access tokens + the request principal + RBAC deps.

This module owns the *authentication* and *authorization* primitives shared by
the HTTP routers and the WebSocket endpoints:

  * `encode_access_token` / `decode_access_token` — short-lived HS256 JWTs,
    signed with `JWT_SECRET_KEY` (kept separate from the Fernet `SECRET_KEY`).
  * `CurrentUser` — the resolved principal (id, role, assigned servers) with the
    scope helpers (`can_access_server`, `scoped_server_filter`).
  * `get_current_user` — FastAPI dependency: reads the access-token cookie,
    decodes it, loads the (active) user, and 401s otherwise.
  * `require_role(*roles)` — dependency factory (403 unless the role matches;
    admin always passes).
  * `ensure_server_access(user, server_id)` — per-server authorization (403 on
    an unassigned server) used inside handlers that resolve a `server_id`.

The refresh-token lifecycle (rotation, reuse detection, revocation) lives in the
auth module's service, not here — this file is import-safe for both routers and
the WS layer.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, Request

from app.core.config import settings
from app.core.constants import Collections, UserRole
from app.core.database import get_database
from app.core.db_utils import safe_object_id
from app.core.errors import http_error

ALGORITHM = "HS256"

# Cookie names — shared by the auth router (set/clear) and the readers here + WS.
ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"


def _secret() -> str:
    s = settings.JWT_SECRET_KEY
    if not s:
        raise RuntimeError(
            "JWT_SECRET_KEY is not configured — set it in .env before using auth."
        )
    return s


# ── Access tokens ────────────────────────────────────────────────────────────

def encode_access_token(*, user_id: str, role: str, username: str) -> str:
    """Sign a short-lived access JWT. Carries only identity + role; the server
    set is loaded fresh from the DB on each request so assignment changes and
    deactivation take effect within one access-token lifetime."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "username": username,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode + verify an access JWT. Raises `jwt.PyJWTError` on invalid/expired."""
    return jwt.decode(token, _secret(), algorithms=[ALGORITHM])


# ── Principal ──────────────────────────────────────────────────────────────--

@dataclass
class CurrentUser:
    id: str
    username: str
    role: str
    server_ids: list[str]
    is_protected: bool

    @classmethod
    def from_doc(cls, doc: dict) -> "CurrentUser":
        return cls(
            id=str(doc["_id"]),
            username=doc.get("username", ""),
            role=doc.get("role", UserRole.VIEWER.value),
            server_ids=[str(s) for s in (doc.get("server_ids") or [])],
            is_protected=bool(doc.get("is_protected", False)),
        )

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN.value

    def can_access_server(self, server_id: str) -> bool:
        """Admin sees every server; everyone else only their assigned set."""
        return self.is_admin or (server_id in self.server_ids)

    def scoped_server_filter(self, field: str = "server_id") -> dict:
        """Mongo fragment to scope a list query to this principal's servers.
        `{}` for admin (unfiltered); `{field: {"$in": [...]}}` otherwise."""
        if self.is_admin:
            return {}
        return {field: {"$in": self.server_ids}}


# ── Resolution + dependencies ──────────────────────────────────────────────--

async def _load_current_user(user_id: str) -> Optional[CurrentUser]:
    oid = safe_object_id(user_id)
    if oid is None:
        return None
    doc = await get_database()[Collections.USERS].find_one({"_id": oid})
    if not doc or not doc.get("is_active", True):
        return None
    return CurrentUser.from_doc(doc)


async def authenticate_access_token(token: Optional[str]) -> Optional[CurrentUser]:
    """Decode an access token and load the (active) user. Returns None on any
    failure — used by both the HTTP dependency and the WebSocket handshake."""
    if not token:
        return None
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "access":
        return None
    return await _load_current_user(payload.get("sub", ""))


async def get_current_user(request: Request) -> CurrentUser:
    """FastAPI dependency — authenticate the request from its access cookie."""
    user = await authenticate_access_token(request.cookies.get(ACCESS_COOKIE))
    if user is None:
        raise http_error(401, "Not authenticated — please sign in.")
    return user


def require_role(*roles: str):
    """Dependency factory: 403 unless the principal's role is in `roles`. Admin
    always passes (it is the superset role)."""
    allowed = set(roles)

    async def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.is_admin or user.role in allowed:
            return user
        raise http_error(403, "You don't have permission to perform this action.")

    return _dep


def ensure_server_access(user: CurrentUser, server_id: str) -> None:
    """Raise 403 unless the principal may act on `server_id` (admin → always)."""
    if not user.can_access_server(server_id):
        raise http_error(403, "You don't have access to this server.")
