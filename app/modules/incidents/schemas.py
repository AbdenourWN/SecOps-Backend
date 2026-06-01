from pydantic import BaseModel, Field, BeforeValidator
from typing import Optional, Dict, Any, List, Annotated
from datetime import datetime
from app.core.datetime_utils import utc_now
# SeverityLevel / IncidentStatus / ActionLevel now live in app.core.constants;
# re-exported here so existing `from ...incidents.schemas import X` keeps working.
from app.core.constants import SeverityLevel, IncidentStatus, ActionLevel

# --- Helpers ---
PyObjectId = Annotated[str, BeforeValidator(str)]


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
    # Phase 28.5.2 — separate field for the manual checklist produced by the
    # post-remediation review's `suggest_manual_remediation` action. Kept
    # distinct from `ai_manual_commands` so the original triage suggestions
    # are not clobbered. `_meta.automation_log_id` links back to the
    # remediation run that produced these commands so the incident page can
    # render "View remediation run →".
    ai_remediation_manual_commands: Optional[List[Dict[str, Any]]] = None
    ai_remediation_manual_commands_meta: Optional[Dict[str, Any]] = None
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


class LatestRemediation(BaseModel):
    """Phase 28.4 — denormalised latest automation_logs row for the incident detail page."""
    automation_log_id: str
    script_id: Optional[str] = None
    script_name: Optional[str] = None
    status: Optional[str] = None
    executed_at: Optional[datetime] = None
    output: Optional[str] = None
    error: Optional[str] = None
    ai_review_id: Optional[str] = None
    ai_review_verdict: Optional[str] = None
    ai_review_summary: Optional[str] = None


class IncidentResponse(IncidentInDB):
    """Response model that converts MongoDB _id to string."""
    id: PyObjectId = Field(alias="_id")
    server_hostname: Optional[str] = None
    # Phase 28.4 — most recent remediation run on this incident + its AI review verdict.
    # Populated by IncidentService.get_by_id; absent on list responses.
    latest_remediation: Optional[LatestRemediation] = None
    # Phase 28.4 — reason text attached when an AI-suggest action of type
    # `suggest_manual_remediation` was approved on this incident.
    ai_manual_commands_reason: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    """Body for PATCH /incidents/{id}/status"""
    status: IncidentStatus
