"""
Response shape for the in-app notification feed (Phase 29).

Light Pydantic model used as the `response_model` for the feed list endpoint —
it documents the contract for the frontend and serialises the Mongo `_id` as a
string `id`. Inserts stay dict-based (matching the rest of the codebase); this
model only describes what goes *out*.
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class NotificationOut(BaseModel):
    id: str
    type: str
    category: str
    severity: str
    title: str
    body: Optional[str] = None
    link: Optional[str] = None
    server_id: Optional[str] = None
    user_id: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    read: bool = False
    read_at: Optional[datetime] = None
    count: int = 1
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class NotificationListResponse(BaseModel):
    """Paginated feed page — same envelope shape as the other list endpoints."""
    total: int
    page: int
    page_size: int
    results: list[NotificationOut]
