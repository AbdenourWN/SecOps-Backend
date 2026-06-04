"""Auth routes (`/api/auth`). `login` + `refresh` are public (no auth dependency);
the rest require an authenticated principal."""
from fastapi import APIRouter, Depends, Request, Response

from app.core.auth import REFRESH_COOKIE, CurrentUser, get_current_user
from app.modules.auth.cookies import clear_auth_cookies, set_auth_cookies
from app.modules.auth.schemas import (
    LoginRequest,
    PasswordChangeRequest,
    PasswordVerifyRequest,
    UserProfile,
)
from app.modules.auth.service import AuthService

router = APIRouter()


def _client(request: Request):
    ip = request.client.host if request.client else None
    return ip, request.headers.get("user-agent")


@router.post("/login", response_model=UserProfile)
async def login(body: LoginRequest, request: Request, response: Response):
    ip, ua = _client(request)
    tokens, profile = await AuthService().login(body.username, body.password, ip, ua)
    set_auth_cookies(response, tokens)
    return profile


@router.post("/refresh", response_model=UserProfile)
async def refresh(request: Request, response: Response):
    ip, ua = _client(request)
    tokens, profile = await AuthService().refresh(request.cookies.get(REFRESH_COOKIE), ip, ua)
    set_auth_cookies(response, tokens)
    return profile


@router.post("/logout")
async def logout(request: Request, response: Response):
    # No auth dependency: revoking the presented refresh token + clearing cookies
    # must work even if the access token has already expired.
    await AuthService().logout(request.cookies.get(REFRESH_COOKIE))
    clear_auth_cookies(response)
    return {"status": "logged_out"}


@router.post("/logout-all")
async def logout_all(response: Response, user: CurrentUser = Depends(get_current_user)):
    await AuthService().logout_all(user.id)
    clear_auth_cookies(response)
    return {"status": "logged_out_all"}


@router.get("/me", response_model=UserProfile)
async def me(user: CurrentUser = Depends(get_current_user)):
    return await AuthService().get_profile(user.id)


@router.post("/verify-password")
async def verify_password(
    body: PasswordVerifyRequest,
    user: CurrentUser = Depends(get_current_user),
):
    """Step-up re-auth for privileged actions (e.g. opening a terminal). Confirms
    the caller's own password; does not issue or rotate any tokens."""
    await AuthService().verify_password_for_user(user.id, body.password)
    return {"status": "verified"}


@router.post("/me/password")
async def change_password(
    body: PasswordChangeRequest,
    response: Response,
    user: CurrentUser = Depends(get_current_user),
):
    await AuthService().change_password(user.id, body.current_password, body.new_password)
    clear_auth_cookies(response)  # all sessions revoked → force re-login
    return {"status": "password_changed"}
