from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, BeforeValidator, Field

from app.core.datetime_utils import utc_now
# AnomalyType / AnomalySeverity / LogObservationStatus now live in
# app.core.constants; re-exported here so existing imports keep working.
from app.core.constants import AnomalyType, AnomalySeverity, LogObservationStatus

PyObjectId = Annotated[str, BeforeValidator(str)]


class LogObservationInDB(BaseModel):
    server_id: str
    type: AnomalyType

    # Content fingerprint used for dedup aggregation
    fingerprint: str = ""

    log_id: Optional[str] = None           # first log that triggered this
    last_log_id: Optional[str] = None      # most recent triggering log
    log_message: Optional[str] = None
    log_timestamp: Optional[datetime] = None
    sample_log_ids: List[str] = []         # up to 5 most recent log IDs

    reasons: List[str] = []
    score: int = 0
    severity: AnomalySeverity

    status: LogObservationStatus = LogObservationStatus.PENDING_REVIEW
    promoted_incident_id: Optional[str] = None

    # Aggregation counters
    occurrence_count: int = 1
    first_seen_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)

    ai_analysis: Optional[str] = None               # legacy string field — kept for backward compat
    ai_analyzed_at: Optional[datetime] = None
    ai_analysis_latest_id: Optional[str] = None      # → ai_analysis._id
    ai_analysis_count: int = 0
    ai_analysis_in_progress: bool = False            # True while triage agent is running
    ai_promotion_recommendation: Optional[str] = None
    ai_manual_commands: Optional[List[Dict[str, Any]]] = None  # sudo/TTY commands from triage

    detected_at: datetime = Field(default_factory=utc_now)
    reviewed_at: Optional[datetime] = None

    class Config:
        populate_by_name = True
        use_enum_values = True


class LogObservationResponse(LogObservationInDB):
    id: PyObjectId = Field(alias="_id")
    server_hostname: Optional[str] = None  # enriched at read time


class LogObservationListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[LogObservationResponse]


class AnomalyStats(BaseModel):
    total: int
    pending: int
    dismissed: int
    promoted: int


def score_to_severity(score: int) -> AnomalySeverity:
    if score >= 5:
        return AnomalySeverity.HIGH
    if score >= 3:
        return AnomalySeverity.MEDIUM
    return AnomalySeverity.LOW
