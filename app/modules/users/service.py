"""User-management service (Phase 20.1) — admin-only CRUD over the `users`
collection. Enforces the permanent-admin guards (the protected admin can't be
deleted, demoted, or disabled) and validates server assignments against real
servers. Any change that removes access (disable / delete / reset) revokes the
target's sessions so it takes effect immediately."""
from __future__ import annotations

from typing import Optional

from app.core.constants import Collections, UserRole
from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.db_utils import safe_object_id
from app.core.errors import http_error
from app.core.security import hash_password


def _role_value(role) -> str:
    return role.value if hasattr(role, "value") else role


class UserService:
    @property
    def _users(self):
        return get_database()[Collections.USERS]

    @property
    def _sessions(self):
        return get_database()[Collections.SESSIONS]

    def _out(self, u: dict) -> dict:
        return {
            "id": str(u["_id"]),
            "username": u.get("username"),
            "email": u.get("email"),
            "role": u.get("role", UserRole.VIEWER.value),
            "server_ids": [str(s) for s in (u.get("server_ids") or [])],
            "is_active": bool(u.get("is_active", True)),
            "is_protected": bool(u.get("is_protected", False)),
            "last_login_at": u.get("last_login_at"),
            "created_at": u.get("created_at"),
        }

    async def _get_or_404(self, user_id: str) -> dict:
        oid = safe_object_id(user_id)
        doc = await self._users.find_one({"_id": oid}) if oid else None
        if not doc:
            raise http_error(404, "User not found.")
        return doc

    async def _validate_server_ids(self, server_ids: list[str]) -> list[str]:
        if not server_ids:
            return []
        oids = []
        for sid in server_ids:
            oid = safe_object_id(sid)
            if oid is None:
                raise http_error(400, f"Invalid server id: {sid}")
            oids.append(oid)
        found = await get_database()[Collections.SERVERS].count_documents({"_id": {"$in": oids}})
        if found != len(set(server_ids)):
            raise http_error(400, "One or more assigned servers do not exist.")
        return [str(s) for s in server_ids]

    async def _revoke_sessions(self, user_id: str) -> None:
        await self._sessions.update_many(
            {"user_id": user_id},
            {"$set": {"revoked": True, "revoked_at": utc_now()}},
        )

    # ── CRUD ────────────────────────────────────────────────────────────────--
    async def list_users(self) -> list[dict]:
        docs = await self._users.find().sort("created_at", -1).to_list(length=500)
        return [self._out(u) for u in docs]

    async def create_user(self, data, created_by: str) -> dict:
        if await self._users.find_one({"username": data.username}):
            raise http_error(409, "A user with that username already exists.")
        role = _role_value(data.role)
        # Admins are global; everyone else must be scoped to real servers.
        server_ids = [] if role == UserRole.ADMIN.value else await self._validate_server_ids(data.server_ids)
        now = utc_now()
        doc = {
            "username": data.username,
            "email": data.email,
            "password_hash": hash_password(data.password),
            "role": role,
            "server_ids": server_ids,
            "is_active": True,
            "is_protected": False,
            "failed_login_count": 0,
            "locked_until": None,
            "last_login_at": None,
            "password_changed_at": now,
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
        }
        res = await self._users.insert_one(doc)
        doc["_id"] = res.inserted_id
        return self._out(doc)

    async def update_user(self, user_id: str, data) -> dict:
        u = await self._get_or_404(user_id)
        protected = bool(u.get("is_protected"))

        if protected:
            if data.role is not None and _role_value(data.role) != UserRole.ADMIN.value:
                raise http_error(403, "The protected admin's role cannot be changed.")
            if data.is_active is False:
                raise http_error(403, "The protected admin cannot be disabled.")

        update: dict = {}
        if data.email is not None:
            update["email"] = data.email
        if data.role is not None:
            role = _role_value(data.role)
            update["role"] = role
            if role == UserRole.ADMIN.value:
                update["server_ids"] = []  # admins are global → drop assignments
        if data.server_ids is not None:
            target_role = update.get("role", u.get("role"))
            update["server_ids"] = (
                [] if target_role == UserRole.ADMIN.value
                else await self._validate_server_ids(data.server_ids)
            )
        if data.is_active is not None:
            update["is_active"] = data.is_active

        if not update:
            return self._out(u)

        update["updated_at"] = utc_now()
        await self._users.update_one({"_id": u["_id"]}, {"$set": update})
        if update.get("is_active") is False:
            await self._revoke_sessions(str(u["_id"]))
        u.update(update)
        return self._out(u)

    async def reset_password(self, user_id: str, new_password: str) -> dict:
        u = await self._get_or_404(user_id)
        await self._users.update_one(
            {"_id": u["_id"]},
            {"$set": {"password_hash": hash_password(new_password), "password_changed_at": utc_now(), "updated_at": utc_now()}},
        )
        await self._revoke_sessions(str(u["_id"]))  # force re-login everywhere
        return {"status": "password_reset"}

    async def delete_user(self, user_id: str, acting_user_id: str) -> dict:
        u = await self._get_or_404(user_id)
        if u.get("is_protected"):
            raise http_error(403, "The protected admin cannot be deleted.")
        if str(u["_id"]) == acting_user_id:
            raise http_error(400, "You cannot delete your own account.")
        await self._users.delete_one({"_id": u["_id"]})
        await self._revoke_sessions(str(u["_id"]))
        return {"status": "deleted"}
