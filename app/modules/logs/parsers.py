"""
Log line parsers for file_watcher. Each parser extracts a UTC timestamp,
severity level, and message from a raw log line. All parsers fall back
gracefully: if the line can't be parsed, they return parsed=False and let
the caller substitute the ingestion time.
"""
import json
import re
from datetime import datetime, timezone
from typing import TypedDict

from app.modules.logs.schemas import LogLevel


class ParsedLogLine(TypedDict):
    timestamp: datetime   # always tz-aware UTC
    level: str            # lowercase LogLevel value
    message: str
    parsed: bool          # False means fallback to ingestion time was used


# ── nginx / apache combined-log timestamp ──
# e.g. [04/May/2026:14:32:15 +0000]
_COMBINED_TS_RE = re.compile(
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]'
)

# ── syslog / raw timestamp ──
# e.g. "May  4 14:32:15" (RFC 3164, no year, no tz)
_SYSLOG_TS_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s'
)

# HTTP status → level mapping for nginx/apache
def _http_level(line: str) -> str:
    m = re.search(r'" (\d{3}) ', line)
    if m:
        code = int(m.group(1))
        if code >= 500:
            return LogLevel.ERROR.value.lower()
        if code >= 400:
            return LogLevel.WARNING.value.lower()
    return LogLevel.INFO.value.lower()


def _parse_raw(line: str, ingestion_time: datetime) -> ParsedLogLine:
    """Try syslog prefix; fallback to ingestion time."""
    m = _SYSLOG_TS_RE.match(line)
    if m:
        ts_str = m.group(1)
        year = ingestion_time.year
        try:
            naive = datetime.strptime(f"{ts_str} {year}", "%b %d %H:%M:%S %Y")
            # Year-rollover: if the parsed month is in the future, it's last year
            if naive.replace(tzinfo=timezone.utc) > ingestion_time:
                naive = naive.replace(year=year - 1)
            ts = naive.replace(tzinfo=timezone.utc)
            message = line[m.end():].strip()
            return ParsedLogLine(
                timestamp=ts,
                level=LogLevel.INFO.value.lower(),
                message=message or line.strip(),
                parsed=True,
            )
        except ValueError:
            pass
    return ParsedLogLine(
        timestamp=ingestion_time,
        level=LogLevel.INFO.value.lower(),
        message=line.strip(),
        parsed=False,
    )


def _parse_combined(line: str, ingestion_time: datetime) -> ParsedLogLine:
    """Parse nginx or apache combined log format."""
    m = _COMBINED_TS_RE.search(line)
    if m:
        try:
            ts = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
            level = _http_level(line)
            return ParsedLogLine(
                timestamp=ts,
                level=level,
                message=line.strip(),
                parsed=True,
            )
        except ValueError:
            pass
    return ParsedLogLine(
        timestamp=ingestion_time,
        level=LogLevel.INFO.value.lower(),
        message=line.strip(),
        parsed=False,
    )


def _parse_json(line: str, ingestion_time: datetime) -> ParsedLogLine:
    """Parse a JSON log line; extract timestamp, level, message if present."""
    try:
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError("not a dict")

        ts = ingestion_time
        parsed = False

        raw_ts = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp")
        if raw_ts:
            try:
                normalized = str(raw_ts).replace("Z", "+00:00")
                ts = datetime.fromisoformat(normalized).astimezone(timezone.utc)
                parsed = True
            except (ValueError, TypeError):
                pass

        raw_level = (obj.get("level") or obj.get("severity") or "info")
        level_str = str(raw_level).lower()
        # Normalize to known levels
        if level_str not in {"info", "warning", "error", "critical", "unknown"}:
            level_str = LogLevel.INFO.value.lower()

        message = (
            obj.get("message") or obj.get("msg") or obj.get("log") or line.strip()
        )

        return ParsedLogLine(
            timestamp=ts,
            level=level_str,
            message=str(message),
            parsed=parsed,
        )
    except (ValueError, json.JSONDecodeError):
        return ParsedLogLine(
            timestamp=ingestion_time,
            level=LogLevel.INFO.value.lower(),
            message=line.strip(),
            parsed=False,
        )


def parse_log_line(line: str, parser_type: str, ingestion_time: datetime) -> ParsedLogLine:
    """
    Dispatch to the correct parser based on parser_type.
    Always returns a valid ParsedLogLine; never raises.
    """
    try:
        pt = parser_type.lower() if parser_type else "raw"
        if pt in ("nginx", "apache"):
            return _parse_combined(line, ingestion_time)
        if pt == "json":
            return _parse_json(line, ingestion_time)
        return _parse_raw(line, ingestion_time)
    except Exception:
        return ParsedLogLine(
            timestamp=ingestion_time,
            level=LogLevel.INFO.value.lower(),
            message=line.strip(),
            parsed=False,
        )
