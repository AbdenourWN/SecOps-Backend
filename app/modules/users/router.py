"""User-management routes (`/api/users`). Admin-only — enforced at the router
include in `main.py` (`require_role("admin")`)."""
from fastapi import APIRouter, Depends

from app.core.auth import CurrentUser, get_current_user
from app.modules.users.schemas import PasswordResetRequest, UserCreate, UserOut, UserUpdate
from app.modules.users.service import UserService

router = APIRouter()


@router.get("", response_model=list[UserOut])
async def list_users():
    return await UserService().list_users()


@router.post("", response_model=UserOut)
async def create_user(body: UserCreate, user: CurrentUser = Depends(get_current_user)):
    return await UserService().create_user(body, created_by=user.id)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(user_id: str, body: UserUpdate):
    return await UserService().update_user(user_id, body)


@router.post("/{user_id}/reset-password")
async def reset_password(user_id: str, body: PasswordResetRequest):
    return await UserService().reset_password(user_id, body.new_password)


@router.delete("/{user_id}")
async def delete_user(user_id: str, user: CurrentUser = Depends(get_current_user)):
    return await UserService().delete_user(user_id, acting_user_id=user.id)
