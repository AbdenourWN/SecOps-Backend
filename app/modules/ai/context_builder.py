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
from app.core.constants import Collections
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
        srv = await db[Collections.SERVERS].find_one(
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
    """Logs live in Elasticsearch (secops-logs-YYYY.MM), not Mongo. Range-query around anchor."""
    from app.core.elasticsearch import get_elasticsearch
    es = get_elasticsearch()
    if not es:
        return []
    delta = timedelta(minutes=window_minutes)
    gte = (anchor - delta).isoformat()
    lte = (anchor + delta).isoformat()
    try:
        result = await es.search(
            index="secops-logs-*",
            body={
                "query": {"bool": {"filter": [
                    {"term": {"server_id": server_id}},
                    {"range": {"timestamp": {"gte": gte, "lte": lte}}},
                ]}},
                "sort": [{"timestamp": {"order": "asc"}}],
                "size": limit,
                "_source": ["timestamp", "level", "message", "source"],
            },
        )
        return [
            {
                "t": h["_source"].get("timestamp", ""),
                "level": h["_source"].get("level", ""),
                "msg": (h["_source"].get("message", "") or "")[:250],
                "src": h["_source"].get("source", ""),
            }
            for h in result["hits"]["hits"]
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
        cursor = db[Collections.INCIDENTS].find(query).sort("detected_at", -1).limit(8)
        incidents = await cursor.to_list(length=8)
        result = []
        for inc in incidents:
            rule_name = ""
            if inc.get("rule_id"):
                try:
                    rule = await db[Collections.RULES].find_one({"_id": ObjectId(str(inc["rule_id"]))}, {"name": 1})
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


async def _fetch_metrics_backward(server_id: str, hours: int, limit: int = 60) -> list:
    """
    Server-overview variant of `_fetch_metrics_window`: pulls metrics from
    `now - hours` to `now` rather than ± around an event anchor. Used by
    `build_server_context` for whole-server analyses.
    """
    try:
        from app.modules.metrics.service import MetricService
        now = datetime.now(timezone.utc)
        from_dt = (now - timedelta(hours=hours)).isoformat()
        to_dt = now.isoformat()
        points = await MetricService().get_latest_metrics(
            server_id=server_id, limit=limit, from_date=from_dt, to_date=to_dt
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


async def _fetch_logs_backward(server_id: str, hours: int, limit: int = 200) -> list:
    """
    Server-overview variant of `_fetch_logs_window`: ES range query for
    `now - hours` to `now`, newest first then sorted asc for readability.
    """
    from app.core.elasticsearch import get_elasticsearch
    es = get_elasticsearch()
    if not es:
        return []
    now = datetime.now(timezone.utc)
    gte = (now - timedelta(hours=hours)).isoformat()
    lte = now.isoformat()
    try:
        result = await es.search(
            index="secops-logs-*",
            body={
                "query": {"bool": {"filter": [
                    {"term": {"server_id": server_id}},
                    {"range": {"timestamp": {"gte": gte, "lte": lte}}},
                ]}},
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": limit,
                "_source": ["timestamp", "level", "message", "source"],
            },
        )
        hits = list(reversed(result["hits"]["hits"]))  # chronological order for reading
        return [
            {
                "t": h["_source"].get("timestamp", ""),
                "level": h["_source"].get("level", ""),
                "msg": (h["_source"].get("message", "") or "")[:250],
                "src": h["_source"].get("source", ""),
            }
            for h in hits
        ]
    except Exception:
        return []


async def _fetch_remediation_history(server_id: str, hours: int = 24, limit: int = 50) -> list:
    """
    Recent automation_logs for this server, enriched with script_name.
    Mirrors the pattern in `automation/service.py:get_history` but scoped
    to a single server + time window.
    """
    db = get_database()
    try:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        cursor = db[Collections.AUTOMATION_LOGS].find(
            {"server_id": server_id, "executed_at": {"$gte": since}}
        ).sort("executed_at", -1).limit(limit)
        runs = await cursor.to_list(length=limit)
        if not runs:
            return []
        script_ids = list({r.get("script_id") for r in runs if r.get("script_id")})
        script_oids = []
        for sid in script_ids:
            try:
                script_oids.append(ObjectId(sid))
            except Exception:
                pass
        scripts_map: dict = {}
        if script_oids:
            sc_cursor = db[Collections.SCRIPTS].find({"_id": {"$in": script_oids}}, {"name": 1})
            sc_docs = await sc_cursor.to_list(length=len(script_oids))
            scripts_map = {str(s["_id"]): s.get("name", "") for s in sc_docs}
        out = []
        for r in runs:
            out.append({
                "executed_at": _safe_str(r.get("executed_at")),
                "script_name": scripts_map.get(r.get("script_id", ""), str(r.get("script_id", ""))),
                "status": r.get("status", ""),
                "output_excerpt": (r.get("output") or "")[:200],
                "error": (r.get("error") or "")[:200],
            })
        return out
    except Exception:
        return []


async def _fetch_recent_anomalies(server_id: str, hours: int = 24) -> list:
    db = get_database()
    try:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        cursor = db[Collections.LOG_OBSERVATIONS].find(
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


def _format_remediations(runs: list) -> str:
    if not runs:
        return "_No remediation runs in the window._"
    rows = ["| Time | Script | Status | Error / Output |", "|---|---|---|---|"]
    for r in runs:
        detail = r["error"] or r["output_excerpt"] or ""
        # collapse newlines so the table renders
        detail = detail.replace("\n", " ").replace("|", "/")[:160]
        rows.append(f"| {r['executed_at']} | {r['script_name']} | {r['status']} | {detail} |")
    return "\n".join(rows)


async def build_server_context(server_id: str, hours: int = 24) -> str:
    """
    Pre-fetch a whole-server snapshot covering `now - hours` to `now`.
    Used by the server-overview AI agent. Returns a markdown string injected
    as the initial user message so the agent has the full picture upfront.

    Range is backward-only (not ± around an event). Layout mirrors
    `build_incident_context` so the agent's familiar with the section ordering.
    """
    (
        server,
        metrics,
        logs,
        incidents,
        anomalies,
        remediations,
    ) = await asyncio.gather(
        _fetch_server_profile(server_id),
        _fetch_metrics_backward(server_id, hours=hours, limit=60),
        _fetch_logs_backward(server_id, hours=hours, limit=200),
        _fetch_recent_incidents(server_id, hours=hours),
        _fetch_recent_anomalies(server_id, hours=hours),
        _fetch_remediation_history(server_id, hours=hours, limit=50),
    )

    lm = server.get("last_metrics") or {}
    bh = server.get("business_hours") or {}
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=hours)

    # Status-specific block: when the server is reachable-but-auth-failed,
    # the captured `auth_failure_reason` is the single most useful clue for
    # diagnostic suggestions, so surface it prominently.
    status_extra = ""
    if server.get("status") == "reachable":
        afr = server.get("auth_failure_reason") or "(not captured)"
        status_extra = f"\n- **Auth failure (raw)**: {afr}"
    elif server.get("status") == "offline":
        status_extra = "\n- **Network probe failed** — diagnostic commands should focus on connectivity / service state."

    ctx = f"""## Server Profile
- **Hostname**: {server.get('hostname', 'unknown')}
- **IP**: {server.get('ip_address', 'unknown')}
- **OS**: {server.get('os_type', 'unknown')}
- **Status**: {server.get('status', 'unknown')} (online={server.get('is_online', False)}){status_extra}
- **Open incidents (cached)**: {server.get('open_incidents_count', 0)}
- **Business hours**: {bh.get('start', '?')}–{bh.get('end', '?')} {bh.get('tz', 'UTC')} on {bh.get('days', [])}
- **AI autonomy level**: {server.get('ai_autonomy_level', 'read_only')}
- **Latest cached metrics**: CPU={lm.get('cpu_usage', '?')}% RAM={lm.get('ram_usage', '?')}% Disk={lm.get('disk_usage', '?')}% (collected {_fmt_dt(lm.get('collected_at'))})

## Analysis Window
- **From**: {_fmt_dt(window_start)}
- **To**: {_fmt_dt(now)}
- **Duration**: {hours}h

## Metric Time-Series (last {hours}h)
{_format_metrics_table(metrics)}

## Logs (last {hours}h, up to 200 lines)
{_format_logs(logs)}

## Incidents in Window
{_format_incidents(incidents)}

## Anomalies in Window
{_format_anomalies(anomalies)}

## Remediation Runs in Window
{_format_remediations(remediations)}
"""
    return ctx.strip()
