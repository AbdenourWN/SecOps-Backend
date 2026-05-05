from pydantic import BaseModel, Field, BeforeValidator, ConfigDict
from typing import List, Optional, Annotated
from enum import Enum
from datetime import datetime
from app.core.datetime_utils import utc_now

# --- Helpers ---
# This tells Pydantic: "If you see an ObjectId, turn it into a string"
PyObjectId = Annotated[str, BeforeValidator(str)]


# --- Shared Logic ---
class TimestampModel(BaseModel):
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class OSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"

class ServerStatus(str, Enum):
    ONLINE = "online"
    REACHABLE = "reachable"   # TCP ok, credentials broken
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    WARNING = "warning"

class CredentialType(str, Enum):
    PASSWORD = "password"
    SSH_KEY = "ssh_key"

# --- Credential Schemas ---
class CredentialInput(BaseModel):
    username: str
    type: CredentialType = CredentialType.PASSWORD
    secret: str 
    passphrase: Optional[str] = None

class CredentialInDB(TimestampModel):
    username: str
    type: CredentialType
    encrypted_secret: str
    encrypted_passphrase: Optional[str] = None

    class Config:
        populate_by_name = True

class CredentialUpdate(BaseModel):
    username: Optional[str] = None
    type: Optional[CredentialType] = None
    secret: Optional[str] = None 
    passphrase: Optional[str] = None


# --- Cached last metric snapshot (written by MetricService every 60s) ---
class LastMetrics(BaseModel):
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    disk_usage: float = 0.0
    collected_at: Optional[datetime] = None


# --- Anomaly Tier 2: business hours config ---
class BusinessHours(BaseModel):
    """
    Business-hours window used by the time-of-day heuristic.
      - start/end:  "HH:MM" 24h, in `tz`
      - days:       ISO weekday list (Mon=1 .. Sun=7)
      - tz:         IANA tz string ("UTC" recommended for v1)
    """
    start: str = "09:00"
    end: str = "18:00"
    days: List[int] = Field(default_factory=lambda: [1, 2, 3, 4, 5])
    tz: str = "UTC"


# --- Detection algorithm tunables (per-server overrides) ---
class DetectionConfig(BaseModel):
    """
    Per-server overrides for the detection and remediation algorithm.
    All fields are optional — omitted fields fall back to the global defaults
    defined as constants in analysis/service.py.
    """
    verification_window_minutes: int = Field(
        default=10, ge=1, le=120,
        description=(
            "Minutes to watch for rule recurrence after a remediation script runs. "
            "If the same rule fires again within this window the fix is considered failed "
            "and a retry is triggered. Raise for critical servers (longer observation); "
            "lower for noisy servers (faster cycle)."
        ),
    )
    max_remediation_attempts: int = Field(
        default=3, ge=1, le=10,
        description=(
            "Maximum number of times the remediation script is retried before giving up "
            "and sending an escalation alert. Higher = more persistent automation. "
            "Lower = faster human escalation."
        ),
    )
    incident_lookback_minutes: int = Field(
        default=30, ge=5, le=1440,
        description=(
            "How far back (minutes) to look for an existing OPEN/VERIFYING incident "
            "when deduplicating. Incidents older than this are treated as stale and a "
            "fresh incident is opened."
        ),
    )
    recurrence_streak_threshold: int = Field(
        default=3, ge=2, le=20,
        description=(
            "How many consecutive times the same script must appear to succeed then have "
            "the problem come back before automation is paused and an alert is sent. "
            "Lower = more aggressive pause. Higher = more tolerance for flapping."
        ),
    )
    recurrence_lookback_hours: float = Field(
        default=2.0, ge=0.25, le=24.0,
        description=(
            "How recent (hours) a previous auto-resolved incident must be to count as "
            "part of the recurrence chain. If the last resolution was older, the streak "
            "resets to 0 and automation runs normally."
        ),
    )
    volume_spike_multiplier: float = Field(
        default=10.0, ge=2.0, le=100.0,
        description=(
            "Trigger a volume-spike anomaly when the current log rate exceeds this "
            "multiple of the server's rolling baseline. Lower = more sensitive. "
            "Higher = only flag extreme spikes."
        ),
    )


# --- Server Schemas ---
class ServerBase(BaseModel):
    hostname: str
    ip_address: str
    os_type: OSType = OSType.LINUX
    port: Optional[int] = None
    # Tier 2 anomaly preferences (optional on create — service applies defaults)
    business_hours: Optional[BusinessHours] = None
    # Detection algorithm tunables (optional — global defaults apply when None)
    detection_config: Optional[DetectionConfig] = None
    

class ServerCreate(ServerBase):
    credential: CredentialInput
    # Novel-pattern warm-up duration in MINUTES.
    #   - 0      = skip warm-up (flag novel patterns from log #1)
    #   - 60     = default (1h)
    #   - up to ~525_600 = 1 year
    # During warm-up, patterns are recorded silently without flagging.
    warmup_minutes: int = Field(default=60, ge=0, le=525_600)

class ServerInDB(TimestampModel, ServerBase):
    credential_id: str

    status: ServerStatus = ServerStatus.UNKNOWN
    is_online: bool = False
    last_health_check: Optional[datetime] = None
    auth_failure_reason: Optional[str] = None

    # Adaptive health-check backoff (internal scheduling state, written by
    # `update_all_server_statuses`).
    consecutive_offline_checks: int = 0
    next_health_check_at: Optional[datetime] = None

    class Config:
        populate_by_name = True

class ServerResponse(TimestampModel, ServerBase):
    id: PyObjectId = Field(alias="_id")

    status: ServerStatus = ServerStatus.UNKNOWN
    auth_failure_reason: Optional[str] = None
    last_health_check: Optional[datetime] = None
    consecutive_offline_checks: int = 0

    # Denormalised counters — maintained by incident write paths, not computed on demand
    open_incidents_count: int = 0

    # Cached last metric snapshot — updated by MetricService every 60s
    last_metrics: Optional[LastMetrics] = None

    # Tier 2 anomaly read-only state (informational; not directly editable)
    pattern_warmup_until: Optional[datetime] = None
    log_rate_baseline: Optional[float] = None
    log_rate_updated_at: Optional[datetime] = None

    class Config:
        populate_by_name = True

class ServerUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_type: Optional[OSType] = None
    port: Optional[int] = None
    business_hours: Optional[BusinessHours] = None
    detection_config: Optional[DetectionConfig] = None

    # Allow updating the stored credential (e.g., changing the password)
    credential: Optional[CredentialUpdate] = None

    # --- Security Challenge (REQUIRED) ---
    # The user MUST provide the CURRENT password/key to authorize the change
    current_secret: str

# 3. Delete Request Schema
class ServerDelete(BaseModel):
    # The user MUST provide the CURRENT password/key to authorize deletion
    current_secret: str


# 4. Anomaly maintenance — restart warm-up with a custom duration
class WarmupResetRequest(BaseModel):
    """Body for POST /api/servers/{id}/reset-warmup."""
    warmup_minutes: int = Field(default=60, ge=0, le=525_600)
    clear_known_patterns: bool = True   # wipe seen-patterns set so warm-up is meaningful