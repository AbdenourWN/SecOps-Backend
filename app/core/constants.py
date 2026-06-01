"""
Single source of truth for cross-module constants.

This module has **zero internal imports** (only the stdlib ``enum``) so any
module — schemas, services, routers, AI graphs — can import from it without
risk of a circular import.

It holds:
  * **Domain enums** — moved here from the per-module ``schemas.py`` files and
    **re-exported** from their original locations (e.g. ``incidents/schemas.py``
    still does ``from app.core.constants import IncidentStatus``). Every existing
    ``from app.modules.<x>.schemas import <Enum>`` keeps working unchanged, and
    there is exactly one class object per enum (so ``isinstance`` checks are
    import-path independent).
  * **New string enums** for values that were previously bare string literals
    scattered across several files (command/action/analysis-type discriminators,
    verdicts, failure reasons …).
  * **`Collections`** — MongoDB collection names.
  * **`WSTopic` / `WSEvent`** — EventBus / WebSocket topic and event-name strings.
  * **`DetectionDefaults` / `Timeouts`** — tunables duplicated across 2+ files.

All enum values match the strings already persisted in MongoDB / sent on the
wire; this module only centralises the definitions, it does not change them.
"""

from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Domain enums  (moved here; re-exported from their original schemas.py)
# ─────────────────────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    """Incident / rule / anomaly severity. Defined in `incidents/schemas.py` historically."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    OPEN = "open"
    VERIFYING = "verifying"          # remediation ran; waiting to see if rule re-fires
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ActionLevel(int, Enum):
    """The PDF "Three Levels"."""
    AUTOMATIC_REMEDIATION = 1   # machine fixes it alone (e.g. block IP), silent
    REMEDIATION_AND_ALERT = 2   # machine fixes it AND notifies the team
    ALERT_ONLY = 3              # machine does nothing but notify


class OSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"


class RuleOSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    COMMON = "common"           # cross-platform (e.g. SQL injection)


class AIAutonomyLevel(str, Enum):
    READ_ONLY = "read_only"     # agent investigates only; output is suggestions
    SUGGEST = "suggest"         # agent proposes mutations; operator approves each


class ServerStatus(str, Enum):
    ONLINE = "online"
    REACHABLE = "reachable"     # TCP ok, credentials broken
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    WARNING = "warning"


class CredentialType(str, Enum):
    PASSWORD = "password"
    SSH_KEY = "ssh_key"


class ScriptLanguage(str, Enum):
    BASH = "bash"
    POWERSHELL = "powershell"
    PYTHON = "python"


class AnomalyType(str, Enum):
    LOG = "log"                 # individual log message flagged
    VOLUME = "volume"           # server-wide log-rate spike


class AnomalySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class LogObservationStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    DISMISSED = "dismissed"
    PROMOTED_TO_INCIDENT = "promoted_to_incident"


# ─────────────────────────────────────────────────────────────────────────────
# New string enums  (previously bare literals in 2+ files; not yet model fields)
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: `owner_type` (rules/scripts) and `*_library_mode` (server) stay typed as
# Pydantic `Literal[...]` in their schemas to avoid changing serialization. These
# enums exist for *service-level comparisons* and share the same string values.

class OwnerType(str, Enum):
    GLOBAL = "global"
    SERVER = "server"


class LibraryMode(str, Enum):
    GLOBAL = "global"
    SERVER = "server"
    BOTH = "both"


class CommandStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    REJECTED = "rejected"


class ActionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ActionType(str, Enum):
    DISMISS_ANOMALY = "dismiss_anomaly"
    PROMOTE_ANOMALY = "promote_anomaly"
    MARK_INCIDENT_FALSE_POSITIVE = "mark_incident_false_positive"
    DISABLE_SCRIPT_FOR_SERVER = "disable_script_for_server"
    DISABLE_RULE_FOR_SERVER = "disable_rule_for_server"
    SUGGEST_MANUAL_REMEDIATION = "suggest_manual_remediation"
    CREATE_SERVER_RULE = "create_server_rule"
    CREATE_SERVER_SCRIPT = "create_server_script"
    SWAP_REMEDIATION_SCRIPT = "swap_remediation_script"
    CREATE_SERVER_RULE_WITH_SCRIPT = "create_server_rule_with_script"


class AnalysisType(str, Enum):
    INCIDENT_TRIAGE = "incident_triage"
    ANOMALY_TRIAGE = "anomaly_triage"
    SERVER_OVERVIEW = "server_overview"
    SCRIPT_EXECUTION_REVIEW = "script_execution_review"
    COMMAND_IMPACT = "command_impact"
    APP_OVERVIEW = "app_overview"


class SourceType(str, Enum):
    INCIDENT = "incident"
    ANOMALY = "anomaly"
    SERVER = "server"
    COMMAND = "command"
    AUTOMATION_LOG = "automation_log"
    APP = "app"


class ReviewVerdict(str, Enum):
    """`automation_logs.ai_review_verdict` + post-execution review outcomes."""
    RESOLVED = "resolved"
    PARTIAL = "partial"
    NO_EFFECT = "no_effect"
    MADE_WORSE = "made_worse"
    REVIEW_FAILED = "review_failed"
    IN_PROGRESS = "in_progress"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AutomationSkippedReason(str, Enum):
    SCRIPT_DISABLED = "script_disabled"
    SCRIPT_MISSING = "script_missing"
    SCRIPT_DISABLED_FOR_SERVER = "script_disabled_for_server"
    RECURRENCE_DETECTED = "recurrence_detected"


class AutomationFailureReason(str, Enum):
    REMEDIATION_EXHAUSTED = "remediation_exhausted"
    PERMISSION_DENIED = "permission_denied"
    EXECUTION_FAILED = "execution_failed"
    UNSAFE_PLACEHOLDER = "unsafe_placeholder"


# ─────────────────────────────────────────────────────────────────────────────
# In-app notification feed  (Phase 29 — persistent, DB-backed bell feed)
# ─────────────────────────────────────────────────────────────────────────────
# Distinct from the email/SMTP "notifications" module (that's outbound alert
# config). These describe a notification *row* shown in the in-app bell + the
# /notifications page. Each row carries `server_id`/`user_id` for future RBAC
# scoping (the per-recipient WS split lands with auth — see feed.py).

class NotificationType(str, Enum):
    # An AI analysis FINISHED SUCCESSFULLY — result ready to view. This is the
    # headline use case: run triage / anomaly / server-overview / app-overview,
    # navigate away, get a clickable "… ready" notification when it completes.
    AI_ANALYSIS_READY = "ai_analysis_ready"
    AI_ANALYSIS_FAILED = "ai_analysis_failed"      # analysis errored / produced no output
    INCIDENT_CREATED = "incident_created"
    INCIDENT_RESOLVED = "incident_resolved"
    REMEDIATION_SUCCEEDED = "remediation_succeeded"
    REMEDIATION_FAILED = "remediation_failed"
    COMMAND_FINISHED = "command_finished"
    ANOMALY_DETECTED = "anomaly_detected"
    SERVER_HEALTH_CHANGED = "server_health_changed"
    AI_SUGGESTIONS_QUEUED = "ai_suggestions_queued"


class NotificationCategory(str, Enum):
    """Coarse grouping — drives the icon + the /notifications page filter."""
    AI = "ai"
    INCIDENT = "incident"
    AUTOMATION = "automation"
    ANOMALY = "anomaly"
    SERVER = "server"


class NotificationSeverity(str, Enum):
    """Drives the row color + which sonner toast variant fires on the live ping."""
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


# ─────────────────────────────────────────────────────────────────────────────
# MongoDB collection names
# ─────────────────────────────────────────────────────────────────────────────

class Collections:
    SERVERS = "servers"
    CREDENTIALS = "credentials"
    INCIDENTS = "incidents"
    RULES = "rules"
    SCRIPTS = "scripts"
    AUTOMATION_LOGS = "automation_logs"
    LOGS = "logs"                                   # Mongo log lines (separate from ES indices)
    METRICS = "metrics"                             # Mongo metrics collection (indexed alongside logs)
    LOG_SOURCES = "log_sources"
    LOG_OBSERVATIONS = "log_observations"
    SERVER_LOG_PATTERNS = "server_log_patterns"
    DISMISSED_FINGERPRINTS = "dismissed_fingerprints"
    REASON_STATS = "reason_stats"
    COMMAND_AUDIT = "command_audit"
    AI_ANALYSIS = "ai_analysis"
    AI_COMMAND = "ai_command"
    AI_ACTIONS = "ai_actions"
    SETTINGS = "settings"                           # SMTP channels + {_id:"llm"} override doc
    NOTIFICATIONS = "notifications"                 # in-app notification feed (bell + /notifications)


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket / EventBus
# ─────────────────────────────────────────────────────────────────────────────

class WSTopic:
    """Flat (global) EventBus topics. Per-server topics use ``server_topic(id, channel)``."""
    SERVERS = "servers"
    SERVERS_STATUS = "servers.status"
    INCIDENTS = "incidents"
    ANOMALIES = "anomalies"
    SCRIPTS = "scripts"
    RULES = "rules"
    AI_ACTIONS = "ai_actions"
    DASHBOARD_SUMMARY = "dashboard.summary"
    AUTOMATION_HISTORY = "automation.history"
    LOG_SOURCES = "log.sources"
    # In-app notification feed. Global for v1 (no identity on the socket yet);
    # the per-user/per-server topic split lands with auth (Phase 20.1).
    NOTIFICATIONS = "notifications"


class WSEvent:
    """Event-name discriminators carried inside AI/automation WS payloads."""
    AI_ANALYSIS_TOKEN = "ai_analysis_token"
    AI_ANALYSIS_COMPLETE = "ai_analysis_complete"
    AUTOMATION_REVIEW_READY = "automation_review_ready"


def server_topic(server_id: str, channel: str) -> str:
    """Build a per-server topic string, e.g. ``servers.<id>.ai``."""
    return f"servers.{server_id}.{channel}"


# ─────────────────────────────────────────────────────────────────────────────
# Detection-algorithm default tunables
# ─────────────────────────────────────────────────────────────────────────────
# These are the fallback defaults for `DetectionConfig` (per-server overrides).
# They are duplicated today between `servers/schemas.py` field defaults and the
# `.get(field, <default>)` fallbacks in `analysis/service.py` — centralised here
# so there is one authoritative value.

class DetectionDefaults:
    VERIFICATION_WINDOW_MINUTES = 10
    MAX_REMEDIATION_ATTEMPTS = 3
    INCIDENT_LOOKBACK_MINUTES = 30
    RECURRENCE_STREAK_THRESHOLD = 3
    RECURRENCE_LOOKBACK_HOURS = 2.0
    VOLUME_SPIKE_MULTIPLIER = 10.0
    ANOMALY_DEDUP_WINDOW_HOURS = 2.0
    ANOMALY_SUPPRESSION_TTL_HOURS = 24.0
    ANOMALY_AUTO_PROMOTE = False
    SCRIPT_REVIEW_ENABLED = False


# ─────────────────────────────────────────────────────────────────────────────
# Command-execution timeouts  (shared by executors + server execute route)
# ─────────────────────────────────────────────────────────────────────────────

class Timeouts:
    COMMAND_DEFAULT_S = 60      # default per-command timeout (read-only probes)
    COMMAND_MAX_S = 300         # 5-min hard cap on any single command
