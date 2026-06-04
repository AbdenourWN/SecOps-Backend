from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.constants import UserRole


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    email: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    server_ids: list[str] = []


class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[UserRole] = None
    server_ids: Optional[list[str]] = None
    is_active: Optional[bool] = None


class PasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    role: str
    server_ids: list[str] = []
    is_active: bool = True
    is_protected: bool = False
    last_login_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
