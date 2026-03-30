from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from enum import Enum


class NotificationChannel(str, Enum):
    EMAIL = "email"


class NotificationConfigCreate(BaseModel):
    """Schema for creating/updating notification config via API"""
    channel: NotificationChannel = NotificationChannel.EMAIL
    enabled: bool = True
    recipients: list[str]                 # ["admin@company.com", "soc@company.com"]
    min_severity: str = "medium"          # Only alert on this severity and above
    smtp_host: Optional[str] = None       # Override .env if needed
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None


class AlertPayload(BaseModel):
    """Internal model passed to notification channels"""
    incident_id: str
    server_id: str
    server_hostname: str
    server_ip: str
    rule_name: str
    severity: str
    description: str
    context: dict = {}
    detected_at: datetime = None
    action_level: int = 3
    remediation_status: Optional[str] = None  # "executed", "failed", or None
