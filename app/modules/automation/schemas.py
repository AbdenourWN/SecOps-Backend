from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum
from app.core.datetime_utils import utc_now

class ScriptLanguage(str, Enum):
    BASH = "bash"
    POWERSHELL = "powershell"
    PYTHON = "python"

class ScriptBase(BaseModel):
    name: str = Field(..., description="e.g., 'Restart Nginx'")
    description: Optional[str] = None
    language: ScriptLanguage = ScriptLanguage.BASH
    content: str = Field(..., description="The actual code to execute")
    target_os: Optional[str] = "linux"
    category: Optional[str] = "recovery"   # diagnostic | containment | recovery
    enabled: bool = True                    # disabled scripts degrade rule to alert-only

class ScriptCreate(ScriptBase):
    pass

class ScriptInDB(ScriptBase):
    id: str = Field(alias="_id")
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    class Config:
        populate_by_name = True

# For the Audit Trail (History of actions taken)
class AutomationLog(BaseModel):
    incident_id: str
    script_id: str
    server_id: str
    executed_at: datetime = Field(default_factory=utc_now)
    status: str # success, failed
    output: Optional[str] = None
    error: Optional[str] = None