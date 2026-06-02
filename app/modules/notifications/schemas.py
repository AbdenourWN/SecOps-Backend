from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timezone
from enum import Enum


class NotificationChannel(str, Enum):
    EMAIL = "email"


class LlmConfigUpdate(BaseModel):
    """Phase 28.6 — runtime LLM provider/model override (stored in `settings`)."""
    provider: Literal["openrouter", "anthropic", "openai"]
    model: str


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
    remediation_status: Optional[str] = None  # "executed", "failed", "exhausted", or None
    # When True, formatting layer should mark the email as a louder escalation
    # (auto-remediation has been attempted MAX times without resolving the issue).
    is_escalation: bool = False
    remediation_attempts: int = 0
    # When True, bypass the per-config `min_severity` gate in `send_alert` — for
    # operationally important emails that must reach whoever got the prior alert
    # regardless of threshold (e.g. a server-recovery email under a critical-only config).
    bypass_min_severity: bool = False
