from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, List, Optional

from pydantic import BaseModel, BeforeValidator, Field


PyObjectId = Annotated[str, BeforeValidator(str)]


def utc_now():
    return datetime.now(timezone.utc)


class AnomalyType(str, Enum):
    LOG = "log"          # individual log message flagged
    VOLUME = "volume"    # server-wide log-rate spike


class AnomalySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class LogObservationStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    DISMISSED = "dismissed"
    PROMOTED_TO_INCIDENT = "promoted_to_incident"


class LogObservationInDB(BaseModel):
    server_id: str
    type: AnomalyType

    log_id: Optional[str] = None
    log_message: Optional[str] = None
    log_timestamp: Optional[datetime] = None

    reasons: List[str] = []
    score: int = 0
    severity: AnomalySeverity

    status: LogObservationStatus = LogObservationStatus.PENDING_REVIEW
    promoted_incident_id: Optional[str] = None

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
