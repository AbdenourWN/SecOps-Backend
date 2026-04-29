from pydantic import BaseModel, Field, field_validator
from typing import Optional, Any, Dict
from datetime import datetime, timezone
from enum import Enum

def utc_now():
    return datetime.now(timezone.utc)

class LogParserType(str, Enum):
    RAW = "raw"
    NGINX = "nginx"
    APACHE = "apache"
    JSON = "json"

class LogSource(BaseModel):
    server_id: str
    name: str  # e.g. "Nginx Access"
    file_path: str  # e.g. "/var/log/nginx/access.log"
    parser_type: LogParserType = LogParserType.RAW
    
    # STATE TRACKING (The Bookmark)
    last_offset: int = 0  # The byte number where we stopped last time
    is_active: bool = True
    last_inode: Optional[int] = None
    last_header: Optional[str] = None 
    error_count: int = 0

    class Config:
        populate_by_name = True

def _validate_file_path(v: str) -> str:
    if not v or not v.strip():
        raise ValueError("file_path cannot be empty")
    if len(v) > 512:
        raise ValueError("file_path too long (max 512 chars)")
    # Null bytes and newlines never appear in real paths and would break
    # the multi-line shell/PowerShell command strings we build at runtime.
    if any(c in v for c in ('\x00', '\r', '\n')):
        raise ValueError("file_path contains invalid characters (null byte or newline)")
    # Reject path traversal components.
    parts = v.replace('\\', '/').split('/')
    if '..' in parts:
        raise ValueError("file_path must not contain '..' path traversal")
    return v


class LogSourceCreate(BaseModel):
    server_id: str
    name: str
    file_path: str
    parser_type: LogParserType = LogParserType.RAW

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        return _validate_file_path(v)


class LogSourceUpdate(BaseModel):
    name: Optional[str] = None
    file_path: Optional[str] = None
    parser_type: Optional[LogParserType] = None
    is_active: Optional[bool] = None

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _validate_file_path(v)

class LogSourceInDB(LogSource):
    id: str = Field(alias="_id")



class LogLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

# Helper to map Syslog Priority IDs (0-7) to our Enum
def map_priority_to_level(priority: str) -> LogLevel:
    p = int(priority)
    if p <= 3: return LogLevel.ERROR    # 0=Emerg, 1=Alert, 2=Crit, 3=Err
    if p == 4: return LogLevel.WARNING  # 4=Warning
    if p <= 6: return LogLevel.INFO     # 5=Notice, 6=Info
    return LogLevel.UNKNOWN

class LogEntryInDB(BaseModel):
    server_id: str
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=utc_now)
    
    # Core Data
    service: str = "system" # e.g., sshd, cron
    level: LogLevel = LogLevel.UNKNOWN
    message: str 
    
    # Raw JSON from journalctl (for debugging/forensics)
    raw_metadata: Optional[Dict[str, Any]] = None

    class Config:
        populate_by_name = True

# Response model for API
class LogResponse(LogEntryInDB):
    id: str = Field(alias="_id")