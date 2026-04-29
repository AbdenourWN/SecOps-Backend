from pydantic import BaseModel, Field, BeforeValidator, ConfigDict
from typing import List, Optional, Annotated
from enum import Enum
from datetime import datetime ,timezone

# --- Helpers ---
# This tells Pydantic: "If you see an ObjectId, turn it into a string"
PyObjectId = Annotated[str, BeforeValidator(str)]

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --- Shared Logic ---
class TimestampModel(BaseModel):
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class OSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"

class ServerStatus(str, Enum):
    ONLINE = "online"
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


# --- Server Schemas ---
class ServerBase(BaseModel):
    hostname: str
    ip_address: str
    os_type: OSType = OSType.LINUX
    port: Optional[int] = None
    # Tier 2 anomaly preferences (optional on create — service applies defaults)
    business_hours: Optional[BusinessHours] = None

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
    last_health_check: Optional[datetime] = None

    # Adaptive health-check backoff (internal scheduling state, written by
    # `update_all_server_statuses`).
    consecutive_offline_checks: int = 0
    next_health_check_at: Optional[datetime] = None

    class Config:
        populate_by_name = True

class ServerResponse(TimestampModel, ServerBase):
    id: PyObjectId = Field(alias="_id")

    status: ServerStatus = ServerStatus.UNKNOWN
    last_health_check: Optional[datetime] = None

    # Adaptive health-check backoff (read-only; informational)
    consecutive_offline_checks: int = 0
    next_health_check_at: Optional[datetime] = None

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