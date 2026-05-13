"""
Pre-flight context builder for AI triage agents.

Gathers server profile, metrics at event time, surrounding logs,
recent incidents and anomalies in one parallel round-trip, then
formats them as a rich markdown block injected into the agent's
initial user message.

This eliminates 2-3 agent tool-call round-trips for the most common
data the agent ALWAYS needs, while still leaving targeted drill-down
tools available for deeper investigation.
"""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from bson import ObjectId

from app.core.database import get_database


def _safe_str(v) -> str:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.isoformat()
    if isinstance(v, ObjectId):
        return str(v)
    return str(v) if v is not None else ""


def _fmt_dt(v) -> str:
    if v is None:
        return "unknown"
    return _safe_str(v)


async def _fetch_server_profile(server_id: str) -> dict:
    db = get_database()
    try:
        srv = await db["servers"].find_one(
            {"_id": ObjectId(server_id)},
            {
                "hostname": 1, "ip_address": 1, "os_type": 1, "port": 1,
                "status": 1, "is_online": 1, "last_metrics": 1,
                "open_incidents_count": 1, "business_hours": 1,
                "ai_autonomy_level": 1, "last_seen_at": 1,
            },
        )
        return srv or {}
    except Exception:
        return {}


async def _fetch_metrics_window(server_id: str, anchor: datetime, window_minutes: int = 15) -> list:
    """Return metric time-series in the ±window_minutes around anchor."""
    try:
        from app.modules.metrics.service import MetricService
        delta = timedelta(minutes=window_minutes)
        from_dt = (anchor - delta).isoformat()
        to_dt = (anchor + delta).isoformat()
        points = await MetricService().get_latest_metrics(
            server_id=server_id, limit=30, from_date=from_dt, to_date=to_dt
        )
        return [
            {
                "t": p.get("timestamp", ""),
                "cpu": p.get("cpu_usage"),
                "ram": p.get("ram_usage"),
                "disk": p.get("disk_usage"),
            }
            for p in (points or [])
        ]
    except Exception:
        return []


async def _fetch_logs_window(server_id: str, anchor: datetime, window_minutes: int = 5, limit: int = 50) -> list:
    db = get_database()
    try:
        delta = timedelta(minutes=window_minutes)
        cursor = db["logs"].find({
            "server_id": server_id,
            "timestamp": {"$gte": anchor - delta, "$lte": anchor + delta},
        }).sort("timestamp", 1).limit(limit)
        logs = await cursor.to_list(length=limit)
        return [
            {
                "t": _safe_str(l.get("timestamp")),
                "level": l.get("level", ""),
                "msg": (l.get("message", "") or "")[:250],
                "src": l.get("source", ""),
            }
            for l in logs
        ]
    except Exception:
        return []


async def _fetch_recent_incidents(server_id: str, hours: int = 24, exclude_id: Optional[str] = None) -> list:
    db = get_database()
    try:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        query: dict = {"server_id": server_id, "detected_at": {"$gte": since}}
        if exclude_id:
            try:
                query["_id"] = {"$ne": ObjectId(exclude_id)}
            except Exception:
                pass
        cursor = db["incidents"].find(query).sort("detected_at", -1).limit(8)
        incidents = await cursor.to_list(length=8)
        result = []
        for inc in incidents:
            rule_name = ""
            if inc.get("rule_id"):
                try:
                    rule = await db["rules"].find_one({"_id": ObjectId(str(inc["rule_id"]))}, {"name": 1})
                    if rule:
                        rule_name = rule.get("name", "")
                except Exception:
                    pass
            result.append({
                "id": str(inc["_id"]),
                "rule": rule_name or str(inc.get("rule_id", "")),
                "severity": inc.get("severity", ""),
                "status": inc.get("status", ""),
                "detected_at": _safe_str(inc.get("detected_at")),
            })
        return result
    except Exception:
        return []


async def _fetch_recent_anomalies(server_id: str, hours: int = 24) -> list:
    db = get_database()
    try:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        cursor = db["log_observations"].find(
            {"server_id": server_id, "last_seen_at": {"$gte": since}}
        ).sort("last_seen_at", -1).limit(8)
        obs = await cursor.to_list(length=8)
        return [
            {
                "severity": o.get("severity", ""),
                "score": round(o.get("score", 0), 2),
                "status": o.get("status", ""),
                "reasons": o.get("reasons", [])[:3],
                "occurrences": o.get("occurrence_count", 1),
                "last_seen": _safe_str(o.get("last_seen_at")),
                "msg": (o.get("log_message", "") or "")[:150],
            }
            for o in obs
        ]
    except Exception:
        return []


def _format_metrics_table(points: list) -> str:
    if not points:
        return "_No metric data in window._"
    rows = ["| Timestamp | CPU % | RAM % | Disk % |", "|---|---|---|---|"]
    for p in points:
        rows.append(
            f"| {p['t']} | {p['cpu'] if p['cpu'] is not None else '—'} "
            f"| {p['ram'] if p['ram'] is not None else '—'} "
            f"| {p['disk'] if p['disk'] is not None else '—'} |"
        )
    return "\n".join(rows)


def _format_logs(logs: list) -> str:
    if not logs:
        return "_No logs in window._"
    lines = []
    for l in logs:
        lines.append(f"[{l['t']}] [{l['level'].upper():7}] {l['msg']}")
    return "```\n" + "\n".join(lines) + "\n```"


def _format_incidents(incidents: list) -> str:
    if not incidents:
        return "_No other incidents in the last 24h._"
    rows = ["| Time | Rule | Severity | Status |", "|---|---|---|---|"]
    for inc in incidents:
        rows.append(f"| {inc['detected_at']} | {inc['rule']} | {inc['severity']} | {inc['status']} |")
    return "\n".join(rows)


def _format_anomalies(anomalies: list) -> str:
    if not anomalies:
        return "_No anomalies in the last 24h._"
    rows = ["| Last seen | Severity | Score | Occurrences | Reasons |", "|---|---|---|---|---|"]
    for a in anomalies:
        rows.append(
            f"| {a['last_seen']} | {a['severity']} | {a['score']} "
            f"| {a['occurrences']} | {', '.join(a['reasons'])} |"
        )
    return "\n".join(rows)


async def build_incident_context(incident_id: str, incident_doc: dict) -> str:
    """
    Pre-fetch all context for an incident triage.
    Returns a rich markdown string injected as the initial user message.
    """
    server_id = str(incident_doc.get("server_id", ""))
    anchor_raw = incident_doc.get("detected_at")
    anchor: datetime = (
        anchor_raw if isinstance(anchor_raw, datetime) else datetime.now(timezone.utc)
    )
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)

    # Parallel fetch
    (
        server,
        metrics,
        logs,
        related_incidents,
        anomalies,
    ) = await asyncio.gather(
        _fetch_server_profile(server_id),
        _fetch_metrics_window(server_id, anchor, window_minutes=15),
        _fetch_logs_window(server_id, anchor, window_minutes=5, limit=50),
        _fetch_recent_incidents(server_id, hours=24, exclude_id=incident_id),
        _fetch_recent_anomalies(server_id, hours=24),
    )

    lm = server.get("last_metrics") or {}
    bh = server.get("business_hours") or {}

    ctx = f"""## Server Profile
- **Hostname**: {server.get('hostname', 'unknown')}
- **IP**: {server.get('ip_address', 'unknown')}
- **OS**: {server.get('os_type', 'unknown')}
- **Status**: {server.get('status', 'unknown')} (online={server.get('is_online', False)})
- **Open incidents**: {server.get('open_incidents_count', 0)}
- **Business hours**: {bh.get('start', '?')}–{bh.get('end', '?')} {bh.get('tz', 'UTC')} on {bh.get('days', [])}
- **AI autonomy level**: {server.get('ai_autonomy_level', 'read_only')}
- **Latest metrics** (cached): CPU={lm.get('cpu_usage', '?')}% RAM={lm.get('ram_usage', '?')}% Disk={lm.get('disk_usage', '?')}% (collected {_fmt_dt(lm.get('collected_at'))})

## Incident Under Investigation
- **ID**: {incident_id}
- **Rule matched**: {str(incident_doc.get('rule_id', '?'))}
- **Severity**: {incident_doc.get('severity', '?')}
- **Status**: {incident_doc.get('status', '?')}
- **Detected at**: {_fmt_dt(incident_doc.get('detected_at'))}
- **Remediation attempts**: {incident_doc.get('remediation_attempts', 0)}
- **Automation skip reason**: {incident_doc.get('automation_skipped_reason') or 'none'}
- **Automation failure reason**: {incident_doc.get('automation_failure_reason') or 'none'}

## Metrics at Event Time (±15 min around {_fmt_dt(anchor)})
{_format_metrics_table(metrics)}

## Surrounding Logs (±5 min around event, up to 50 lines)
{_format_logs(logs)}

## Other Incidents in Last 24h (same server)
{_format_incidents(related_incidents)}

## Anomalies in Last 24h (same server)
{_format_anomalies(anomalies)}
"""
    return ctx.strip()


async def build_anomaly_context(observation_id: str, obs_doc: dict) -> str:
    """
    Pre-fetch all context for an anomaly triage.
    Returns a rich markdown string injected as the initial user message.
    """
    server_id = str(obs_doc.get("server_id", ""))
    anchor_raw = obs_doc.get("last_seen_at") or obs_doc.get("first_seen_at")
    anchor: datetime = (
        anchor_raw if isinstance(anchor_raw, datetime) else datetime.now(timezone.utc)
    )
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)

    # Parallel fetch
    (
        server,
        metrics,
        logs,
        related_incidents,
        anomalies,
    ) = await asyncio.gather(
        _fetch_server_profile(server_id),
        _fetch_metrics_window(server_id, anchor, window_minutes=15),
        _fetch_logs_window(server_id, anchor, window_minutes=5, limit=50),
        _fetch_recent_incidents(server_id, hours=24),
        _fetch_recent_anomalies(server_id, hours=24),
    )

    lm = server.get("last_metrics") or {}
    bh = server.get("business_hours") or {}

    ctx = f"""## Server Profile
- **Hostname**: {server.get('hostname', 'unknown')}
- **IP**: {server.get('ip_address', 'unknown')}
- **OS**: {server.get('os_type', 'unknown')}
- **Status**: {server.get('status', 'unknown')} (online={server.get('is_online', False)})
- **Open incidents**: {server.get('open_incidents_count', 0)}
- **Business hours**: {bh.get('start', '?')}–{bh.get('end', '?')} {bh.get('tz', 'UTC')} on {bh.get('days', [])}
- **AI autonomy level**: {server.get('ai_autonomy_level', 'read_only')}
- **Latest metrics** (cached): CPU={lm.get('cpu_usage', '?')}% RAM={lm.get('ram_usage', '?')}% Disk={lm.get('disk_usage', '?')}% (collected {_fmt_dt(lm.get('collected_at'))})

## Anomaly Under Investigation
- **ID**: {observation_id}
- **Type**: {obs_doc.get('type', '?')}
- **Severity**: {obs_doc.get('severity', '?')}
- **Status**: {obs_doc.get('status', '?')}
- **Score**: {obs_doc.get('score', '?')}
- **Occurrence count**: {obs_doc.get('occurrence_count', 1)}
- **First seen**: {_fmt_dt(obs_doc.get('first_seen_at'))}
- **Last seen**: {_fmt_dt(obs_doc.get('last_seen_at'))}
- **Trigger reasons**: {', '.join(obs_doc.get('reasons', []))}
- **Log message**: {(obs_doc.get('log_message') or 'N/A')[:400]}

## Metrics at Event Time (±15 min around {_fmt_dt(anchor)})
{_format_metrics_table(metrics)}

## Surrounding Logs (±5 min around event, up to 50 lines)
{_format_logs(logs)}

## Incidents in Last 24h (same server)
{_format_incidents(related_incidents)}

## Other Anomalies in Last 24h (same server)
{_format_anomalies(anomalies)}
"""
    return ctx.strip()
