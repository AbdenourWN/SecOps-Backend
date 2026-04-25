from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum

# Re-export incident schemas from their new home for backward compatibility
from app.modules.incidents.schemas import (
    SeverityLevel,
    IncidentStatus,
    IncidentInDB,
    ActionLevel,
)

def utc_now():
    return datetime.now(timezone.utc)

class RuleOSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    COMMON = "common"  # For things like SQL Injection that can happen anywhere


# --- 1. The Rule (Stored in DB) ---
class DetectionRule(BaseModel):
    name: str = Field(..., description="e.g. 'SSH Failed Login'")
    pattern: str = Field(..., description="Regex pattern to find in logs")
    severity: SeverityLevel
    action_level: ActionLevel
    description: Optional[str] = None
    enabled: bool = True

    os_type: RuleOSType = RuleOSType.LINUX
    tags: List[str] = []

    remediation_script_id: Optional[str] = None
    remediation_script_id_windows: Optional[str] = None  # Windows override for cross-OS rules

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: Optional[datetime] = None

class DetectionRuleInDB(DetectionRule):
    id: str = Field(alias="_id")