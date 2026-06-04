from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class PasswordVerifyRequest(BaseModel):
    """Step-up re-auth (e.g. before opening a privileged terminal)."""
    password: str


class UserProfile(BaseModel):
    """The `/me` + login response shape — what the frontend AuthProvider needs."""
    id: str
    username: str
    email: Optional[str] = None
    role: str
    server_ids: list[str] = []
    is_protected: bool = False
    is_active: bool = True
    last_login_at: Optional[datetime] = None
