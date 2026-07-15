"""Auth cookie helpers (Phase 20.1).

Three cookies: `access_token` (httpOnly, path `/api`), `refresh_token` (httpOnly,
path-scoped to `/api/auth` so it's only sent to the refresh/logout endpoints),
and `csrf_token` (readable by JS, path `/`) for the double-submit CSRF check.
"""
from __future__ import annotations

from fastapi import Response

from app.core.auth import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE
from app.core.config import settings


def set_auth_cookies(response: Response, tokens: dict) -> None:
    secure = settings.AUTH_COOKIE_SECURE
    samesite = settings.AUTH_COOKIE_SAMESITE
    domain = settings.AUTH_COOKIE_DOMAIN or None
    access_max = settings.ACCESS_TOKEN_TTL_MINUTES * 60
    refresh_max = settings.REFRESH_TOKEN_TTL_DAYS * 24 * 3600

    # Path "/" (not "/api") so the Next.js proxy can optimistically gate page
    # navigations on the cookie's presence; the backend reads it for /api/* too.
    response.set_cookie(
        ACCESS_COOKIE, tokens["access_token"],
        max_age=access_max, httponly=True, secure=secure, samesite=samesite, path="/", domain=domain,
    )
    response.set_cookie(
        REFRESH_COOKIE, tokens["refresh_token"],
        max_age=refresh_max, httponly=True, secure=secure, samesite=samesite, path="/api/auth", domain=domain,
    )
    # Readable by JS so the SPA can echo it back in the X-CSRF-Token header.
    response.set_cookie(
        CSRF_COOKIE, tokens["csrf_token"],
        max_age=refresh_max, httponly=False, secure=secure, samesite=samesite, path="/", domain=domain,
    )


def clear_auth_cookies(response: Response) -> None:
    domain = settings.AUTH_COOKIE_DOMAIN or None
    response.delete_cookie(ACCESS_COOKIE, path="/", domain=domain)
    response.delete_cookie(REFRESH_COOKIE, path="/api/auth", domain=domain)
    response.delete_cookie(CSRF_COOKIE, path="/", domain=domain)
