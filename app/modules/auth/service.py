"""
Auth service (Phase 20.1) — login, session lifecycle, and the protected-admin
bootstrap.

Sessions are **rotating refresh tokens**: each refresh issues a new token in the
same `family_id` and marks the old row `rotated_to`. Presenting an already-rotated
or revoked token is treated as **reuse** and revokes the entire family (forces a
fresh login) — the standard stolen-refresh-token mitigation. Only the SHA-256 of
each refresh token is stored; the raw value lives only in the client's httpOnly
cookie.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.core.auth import encode_access_token
from app.core.config import settings
from app.core.constants import Collections, UserRole
from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.db_utils import safe_object_id
from app.core.errors import http_error
from app.core.rate_limit import check_rate_limit
from app.core.security import (
    hash_password,
    hash_token,
    make_refresh_token,
    verify_password,
)

logger = logging.getLogger(__name__)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Defensive tz-normalise (Motor is tz_aware, but reads from elsewhere may not be)."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class AuthService:
    @property
    def _users(self):
        return get_database()[Collections.USERS]

    @property
    def _sessions(self):
        return get_database()[Collections.SESSIONS]

    # ── Login ─────────────────────────────────────────────────────────────────
    async def login(self, username: str, password: str, ip: Optional[str], user_agent: Optional[str]):
        # Coarse per-(ip, username) throttle on top of the durable account lockout.
        rl = await check_rate_limit(f"login:{ip or 'unknown'}", username or "-")
        if not rl.allowed:
            raise http_error(429, f"Too many login attempts — try again in {rl.retry_after_s}s.")

        now = utc_now()
        invalid = http_error(401, "Invalid username or password.")
        user = await self._users.find_one({"username": username})
        if not user:
            raise invalid

        locked_until = _aware(user.get("locked_until"))
        if locked_until and locked_until > now:
            raise http_error(401, "Account temporarily locked after repeated failures — try again later.")

        if not verify_password(password, user.get("password_hash", "")):
            await self._register_failed_attempt(user, now)
            raise invalid

        if not user.get("is_active", True):
            raise http_error(403, "This account is disabled.")

        await self._users.update_one(
            {"_id": user["_id"]},
            {"$set": {"failed_login_count": 0, "locked_until": None, "last_login_at": now}},
        )
        tokens = await self._issue_session(user, ip, user_agent, now)
        return tokens, self._profile(user)

    async def _register_failed_attempt(self, user: dict, now: datetime) -> None:
        count = (user.get("failed_login_count") or 0) + 1
        update: dict = {"failed_login_count": count}
        if count >= settings.LOGIN_MAX_ATTEMPTS:
            update["locked_until"] = now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
            update["failed_login_count"] = 0  # reset; the lock is the gate now
        await self._users.update_one({"_id": user["_id"]}, {"$set": update})

    # ── Session issue / rotate ──────────────────────────────────────────────--
    async def _issue_session(self, user: dict, ip, user_agent, now: datetime, family_id: Optional[str] = None) -> dict:
        raw_refresh = make_refresh_token()
        family_id = family_id or secrets.token_hex(16)
        expires_at = now + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)
        await self._sessions.insert_one({
            "user_id": str(user["_id"]),
            "token_hash": hash_token(raw_refresh),
            "family_id": family_id,
            "issued_at": now,
            "expires_at": expires_at,
            "last_used_at": now,
            "revoked": False,
            "revoked_at": None,
            "rotated_to": None,
            "user_agent": user_agent,
            "ip": ip,
        })
        access = encode_access_token(
            user_id=str(user["_id"]),
            role=user.get("role", UserRole.VIEWER.value),
            username=user.get("username", ""),
        )
        return {
            "access_token": access,
            "refresh_token": raw_refresh,
            "csrf_token": secrets.token_urlsafe(24),
        }

    # ── Refresh (rotate + reuse detection) ──────────────────────────────────--
    async def refresh(self, raw_refresh: Optional[str], ip, user_agent):
        if not raw_refresh:
            raise http_error(401, "Not authenticated — please sign in.")
        now = utc_now()
        sess = await self._sessions.find_one({"token_hash": hash_token(raw_refresh)})
        if not sess:
            raise http_error(401, "Session expired — please sign in again.")

        # Reuse: an already-rotated or revoked token means the family is compromised.
        if sess.get("revoked") or sess.get("rotated_to"):
            await self._sessions.update_many(
                {"family_id": sess["family_id"]},
                {"$set": {"revoked": True, "revoked_at": now}},
            )
            raise http_error(401, "Session is no longer valid — please sign in again.")

        if _aware(sess["expires_at"]) <= now:
            await self._sessions.update_one({"_id": sess["_id"]}, {"$set": {"revoked": True, "revoked_at": now}})
            raise http_error(401, "Session expired — please sign in again.")

        user = await self._users.find_one({"_id": safe_object_id(sess["user_id"])})
        if not user or not user.get("is_active", True):
            await self._sessions.update_one({"_id": sess["_id"]}, {"$set": {"revoked": True, "revoked_at": now}})
            raise http_error(401, "Session is no longer valid — please sign in again.")

        tokens = await self._issue_session(user, ip, user_agent, now, family_id=sess["family_id"])
        await self._sessions.update_one(
            {"_id": sess["_id"]},
            {"$set": {"rotated_to": hash_token(tokens["refresh_token"]), "last_used_at": now}},
        )
        return tokens, self._profile(user)

    # ── Logout ────────────────────────────────────────────────────────────────
    async def logout(self, raw_refresh: Optional[str]) -> None:
        if raw_refresh:
            await self._sessions.update_one(
                {"token_hash": hash_token(raw_refresh)},
                {"$set": {"revoked": True, "revoked_at": utc_now()}},
            )

    async def logout_all(self, user_id: str) -> None:
        await self._sessions.update_many(
            {"user_id": user_id},
            {"$set": {"revoked": True, "revoked_at": utc_now()}},
        )

    # ── Step-up re-auth (verify current password) ──────────────────────────────
    async def verify_password_for_user(self, user_id: str, password: str) -> None:
        """Confirm `password` matches the *currently authenticated* user's hash.

        Used as a step-up gate (e.g. before opening a privileged terminal). The
        caller already holds a valid session, but we still throttle per-user so a
        hijacked tab can't be used as a password-guessing oracle, and we return a
        generic error on any failure (no account/active-state disclosure)."""
        rl = await check_rate_limit("verify-pw", user_id)
        if not rl.allowed:
            raise http_error(429, f"Too many attempts — try again in {rl.retry_after_s}s.")
        user = await self._users.find_one({"_id": safe_object_id(user_id)})
        if (
            not user
            or not user.get("is_active", True)
            or not verify_password(password, user.get("password_hash", ""))
        ):
            raise http_error(401, "Password is incorrect.")

    # ── Change own password ───────────────────────────────────────────────────
    async def change_password(self, user_id: str, current_password: str, new_password: str) -> None:
        user = await self._users.find_one({"_id": safe_object_id(user_id)})
        if not user or not verify_password(current_password, user.get("password_hash", "")):
            raise http_error(400, "Current password is incorrect.")
        await self._users.update_one(
            {"_id": user["_id"]},
            {"$set": {"password_hash": hash_password(new_password), "password_changed_at": utc_now()}},
        )
        await self.logout_all(str(user["_id"]))  # invalidate every existing session

    # ── Profile ─────────────────────────────────────────────────────────────--
    def _profile(self, user: dict) -> dict:
        return {
            "id": str(user["_id"]),
            "username": user.get("username"),
            "email": user.get("email"),
            "role": user.get("role", UserRole.VIEWER.value),
            "server_ids": [str(s) for s in (user.get("server_ids") or [])],
            "is_protected": bool(user.get("is_protected", False)),
            "is_active": bool(user.get("is_active", True)),
            "last_login_at": user.get("last_login_at"),
        }

    async def get_profile(self, user_id: str) -> dict:
        user = await self._users.find_one({"_id": safe_object_id(user_id)})
        if not user:
            raise http_error(401, "Not authenticated — please sign in.")
        return self._profile(user)


async def ensure_initial_admin() -> None:
    """Startup bootstrap — create the permanent protected admin if no admin
    exists and `INITIAL_ADMIN_PASSWORD` is set. Idempotent + safe to re-run."""
    users = get_database()[Collections.USERS]
    if await users.find_one({"role": UserRole.ADMIN.value}):
        return
    password = settings.INITIAL_ADMIN_PASSWORD
    if not password:
        logger.warning("No admin user and INITIAL_ADMIN_PASSWORD is unset — create one via seed.py or set it in .env")
        return
    now = utc_now()
    await users.insert_one({
        "username": settings.INITIAL_ADMIN_USERNAME,
        "email": None,
        "password_hash": hash_password(password),
        "role": UserRole.ADMIN.value,
        "server_ids": [],
        "is_active": True,
        "is_protected": True,
        "failed_login_count": 0,
        "locked_until": None,
        "last_login_at": None,
        "password_changed_at": now,
        "created_by": None,
        "created_at": now,
        "updated_at": now,
    })
    logger.info("Bootstrapped protected admin user '%s'", settings.INITIAL_ADMIN_USERNAME)
