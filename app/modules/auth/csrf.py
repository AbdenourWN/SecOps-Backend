"""Double-submit CSRF protection (Phase 20.1).

Defense-in-depth on top of SameSite=Lax cookies: for cookie-authenticated
state-changing requests the `X-CSRF-Token` header must equal the readable
`csrf_token` cookie. A cross-site attacker can neither read the cookie value
nor set a custom header cross-origin, so a forged request fails the check.

Only enforced when the access cookie is present (i.e. a cookie-auth request);
purely unauthenticated requests are rejected downstream by `get_current_user`.
`login`/`refresh` are exempt — they establish the session (refresh is already
protected by its path-scoped Lax cookie).
"""
from __future__ import annotations

import secrets

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.auth import ACCESS_COOKIE, CSRF_COOKIE

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_EXEMPT_PATHS = {"/api/auth/login", "/api/auth/refresh"}


async def csrf_protect(request: Request, call_next):
    path = request.url.path
    if (
        request.method not in _SAFE_METHODS
        and path.startswith("/api/")
        and path not in _EXEMPT_PATHS
        and request.cookies.get(ACCESS_COOKIE)
    ):
        header = request.headers.get("x-csrf-token")
        cookie = request.cookies.get(CSRF_COOKIE)
        if not header or not cookie or not secrets.compare_digest(header, cookie):
            return JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid."})
    return await call_next(request)
