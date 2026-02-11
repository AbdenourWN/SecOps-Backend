from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum

def utc_now():
    return datetime.now(timezone.utc)

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

# Matches the PDF "Three Levels"
class ActionLevel(int, Enum):
    # Level 1: Machine fixes it alone. (Example: Block IP)
    # Status becomes 'RESOLVED' automatically.
    AUTOMATIC_REMEDIATION = 1 
    
    # Level 2: Machine fixes it AND notifies the team.
    # Status becomes 'RESOLVED' automatically.
    REMEDIATION_AND_ALERT = 2     
    
    # Level 3: Machine does NOTHING but notify. 
    # Status stays 'OPEN' until a human closes it.
    ALERT_ONLY = 3

# --- 1. The Rule (Stored in DB) ---
class DetectionRule(BaseModel):
    name: str = Field(..., description="e.g. 'SSH Failed Login'")
    pattern: str = Field(..., description="Regex pattern to find in logs")
    severity: SeverityLevel
    action_level: ActionLevel
    description: Optional[str] = None
    enabled: bool = True

    remediation_script_id: Optional[str] = None

class DetectionRuleInDB(DetectionRule):
    id: str = Field(alias="_id")

# --- 2. The Incident (The Result) ---
class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class IncidentInDB(BaseModel):
    server_id: str
    rule_id: str
    log_id: str # Link back to the specific log line
    
    severity: SeverityLevel
    status: IncidentStatus = IncidentStatus.OPEN
    
    detected_at: datetime = Field(default_factory=utc_now)
    description: str # Copied from rule name for easy reading

    class Config:
        populate_by_name = True