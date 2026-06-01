from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime
from app.core.datetime_utils import utc_now

# Re-export shared enums from their canonical home for backward compatibility.
# SeverityLevel / IncidentStatus / ActionLevel / RuleOSType all live in
# app.core.constants now; IncidentInDB still comes from incidents.schemas.
from app.core.constants import SeverityLevel, IncidentStatus, ActionLevel, RuleOSType
from app.modules.incidents.schemas import IncidentInDB


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

    # Phase 28.5 — per-server library scoping
    owner_type: Literal["global", "server"] = "global"
    owner_id: Optional[str] = None

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: Optional[datetime] = None

class DetectionRuleInDB(DetectionRule):
    id: str = Field(alias="_id")