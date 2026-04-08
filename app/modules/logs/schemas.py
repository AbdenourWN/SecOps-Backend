from pydantic import BaseModel, Field
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

class LogSourceCreate(BaseModel):
    server_id: str
    name: str
    file_path: str
    parser_type: LogParserType = LogParserType.RAW

class LogSourceUpdate(BaseModel):
    name: Optional[str] = None
    file_path: Optional[str] = None
    parser_type: Optional[LogParserType] = None
    is_active: Optional[bool] = None

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