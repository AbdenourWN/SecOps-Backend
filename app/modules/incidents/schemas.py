from pydantic import BaseModel, Field, BeforeValidator
from typing import Optional, Dict, Any, List, Annotated
from datetime import datetime
from enum import Enum
from app.core.datetime_utils import utc_now

# --- Helpers ---
PyObjectId = Annotated[str, BeforeValidator(str)]


# --- Enums ---
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class IncidentStatus(str, Enum):
    OPEN = "open"
    VERIFYING = "verifying"   # remediation ran; waiting to see if rule re-fires
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
    auto_resolved_at: Optional[datetime] = None
    description: str  # Copied from rule name for easy reading

    # Extracted context from regex match (e.g., {"source_ip": "1.2.3.4", "username": "root"})
    context: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[str] = None           # legacy string field — kept for backward compat
    ai_analysis_latest_id: Optional[str] = None  # → ai_analysis._id (latest triage run)
    ai_analysis_count: int = 0
    ai_analysis_in_progress: bool = False        # True while triage agent is running
    ai_manual_commands: Optional[List[Dict[str, Any]]] = None  # sudo/TTY commands from triage
    # Set when a rule's linked script was disabled/missing at fire time
    automation_skipped_reason: Optional[str] = None
    # Set when remediation was attempted but failed in a structural way
    # ("remediation_exhausted" after MAX retries; "permission_denied" reserved for Phase 20.6)
    automation_failure_reason: Optional[str] = None

    # Verification / retry tracking
    remediation_attempts: int = 0
    last_remediation_at: Optional[datetime] = None
    verification_until: Optional[datetime] = None

    # Recurrence tracking — counts consecutive auto-resolve → recurrence cycles
    # for the same (server, rule) chain. Resets when an operator manually resolves.
    recurrence_streak: int = 0

    class Config:
        populate_by_name = True


class IncidentResponse(IncidentInDB):
    """Response model that converts MongoDB _id to string."""
    id: PyObjectId = Field(alias="_id")
    server_hostname: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    """Body for PATCH /incidents/{id}/status"""
    status: IncidentStatus
