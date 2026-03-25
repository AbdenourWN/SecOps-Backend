from pydantic import BaseModel, Field, BeforeValidator
from typing import Optional, Dict, Any, Annotated
from datetime import datetime, timezone
from enum import Enum

# --- Helpers ---
PyObjectId = Annotated[str, BeforeValidator(str)]

def utc_now():
    return datetime.now(timezone.utc)


# --- Enums ---
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

# Matches the PDF "Three Levels"
class ActionLevel(int, Enum):
    # Level 1: Machine fixes it alone. (Example: Block IP)
    AUTOMATIC_REMEDIATION = 1
    # Level 2: Machine fixes it AND notifies the team.
    REMEDIATION_AND_ALERT = 2
    # Level 3: Machine does NOTHING but notify.
    ALERT_ONLY = 3


# --- Models ---
class IncidentInDB(BaseModel):
    server_id: str
    rule_id: str
    log_id: str  # Link back to the specific log line

    severity: SeverityLevel
    status: IncidentStatus = IncidentStatus.OPEN

    detected_at: datetime = Field(default_factory=utc_now)
    resolved_at: Optional[datetime] = None
    description: str  # Copied from rule name for easy reading

    # Extracted context from regex match (e.g., {"source_ip": "1.2.3.4", "username": "root"})
    context: Optional[Dict[str, Any]] = None
    # AI analysis result (saved after manual or auto AI analysis)
    ai_analysis: Optional[str] = None

    class Config:
        populate_by_name = True


class IncidentResponse(IncidentInDB):
    """Response model that converts MongoDB _id to string."""
    id: PyObjectId = Field(alias="_id")


class IncidentStatusUpdate(BaseModel):
    """Body for PATCH /incidents/{id}/status"""
    status: IncidentStatus
