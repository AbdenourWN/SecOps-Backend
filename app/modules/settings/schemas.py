from pydantic import BaseModel, Field
from typing import Optional


class SystemSettingsUpdate(BaseModel):
    max_concurrent_servers: Optional[int] = Field(None, ge=1, le=200)


class SystemSettingsResponse(BaseModel):
    max_concurrent_servers: int
    env_default: int
