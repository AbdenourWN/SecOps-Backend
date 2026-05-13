"""
Read-only LangChain tools for the AI triage agent.

All tools call get_database() directly (consistent with the rest of the codebase).
Each tool caps its output at ~2 KB so the LLM context stays bounded.
These tools are always available regardless of ai_autonomy_level.
"""
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from bson import ObjectId
from langchain_core.tools import tool

from app.core.database import get_database


def _safe_str(v) -> str:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.isoformat()
    if isinstance(v, ObjectId):
        return str(v)
    return str(v) if v is not None else ""


def _serialize(doc: dict) -> dict:
    return {k: _safe_str(v) if isinstance(v, (datetime, ObjectId)) else v for k, v in doc.items()}


@tool
async def get_incident(incident_id: str) -> str:
    """
    Fetch an incident by ID along with its matched detection rule.
    Returns JSON with incident fields + rule name/pattern/severity.
    """
    db = get_database()
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return json.dumps({"error": f"Invalid incident_id: {incident_id}"})

    inc = await db["incidents"].find_one({"_id": oid})
    if not inc:
        return json.dumps({"error": "Incident not found"})

    inc["_id"] = str(inc["_id"])
    inc["server_id"] = str(inc.get("server_id", ""))
    inc["rule_id"] = str(inc.get("rule_id", ""))
    inc["log_id"] = str(inc.get("log_id", "")) if inc.get("log_id") else None

    # Enrich with rule
    rule = None
    if inc.get("rule_id"):
        try:
            rule = await db["rules"].find_one({"_id": ObjectId(inc["rule_id"])})
        except Exception:
            pass

    result = {
        "incident": {k: _safe_str(v) if isinstance(v, (datetime, ObjectId)) else v for k, v in inc.items()},
        "rule": {
            "name": rule.get("name", "") if rule else "",
            "pattern": rule.get("pattern", "") if rule else "",
            "severity": rule.get("severity", "") if rule else "",
            "os_type": rule.get("os_type", "") if rule else "",
        } if rule else None,
    }
    return json.dumps(result, default=str)[:3000]


@tool
async def get_recent_logs(server_id: str, limit: int = 20, level: Optional[str] = None) -> str:
    """
    Fetch recent log entries for a server from MongoDB.
    level can be 'error', 'warning', 'info' to filter by severity.
    Returns a JSON list of log messages with timestamps, capped at 20 entries.
    """
    db = get_database()
    limit = min(limit, 20)
    query: dict = {"server_id": server_id}
    if level:
        query["level"] = level

    cursor = db["logs"].find(query).sort("timestamp", -1).limit(limit)
    logs = await cursor.to_list(length=limit)

    result = [
        {
            "timestamp": _safe_str(l.get("timestamp")),
            "level": l.get("level", ""),
            "message": (l.get("message", "") or "")[:300],
            "source": l.get("source", ""),
        }
        for l in reversed(logs)
    ]
    return json.dumps(result, default=str)[:3000]


@tool
async def get_related_incidents(server_id: str, rule_id: Optional[str] = None, hours: int = 24) -> str:
    """
    Fetch recent incidents on the same server, optionally filtered to the same rule.
    Useful for spotting recurrence patterns. Returns up to 10 incidents.
    """
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    query: dict = {"server_id": server_id, "detected_at": {"$gte": since}}
    if rule_id:
        query["rule_id"] = rule_id

    cursor = db["incidents"].find(query).sort("detected_at", -1).limit(10)
    incidents = await cursor.to_list(length=10)

    result = [
        {
            "id": str(i["_id"]),
            "rule_id": str(i.get("rule_id", "")),
            "severity": i.get("severity", ""),
            "status": i.get("status", ""),
            "detected_at": _safe_str(i.get("detected_at")),
            "description": (i.get("description", "") or "")[:200],
        }
        for i in incidents
    ]
    return json.dumps(result, default=str)[:3000]


@tool
async def get_server_metrics(server_id: str) -> str:
    """
    Fetch the latest cached metrics snapshot for a server (CPU, RAM, disk).
    Returns the last_metrics snapshot from the server document.
    """
    db = get_database()
    try:
        oid = ObjectId(server_id)
    except Exception:
        return json.dumps({"error": f"Invalid server_id: {server_id}"})

    server = await db["servers"].find_one(
        {"_id": oid},
        {"last_metrics": 1, "hostname": 1, "status": 1},
    )
    if not server:
        return json.dumps({"error": "Server not found"})

    metrics = server.get("last_metrics") or {}
    return json.dumps({
        "hostname": server.get("hostname", ""),
        "status": server.get("status", ""),
        "cpu_usage": metrics.get("cpu_usage"),
        "ram_usage": metrics.get("ram_usage"),
        "disk_usage": metrics.get("disk_usage"),
        "collected_at": _safe_str(metrics.get("collected_at")) if metrics.get("collected_at") else None,
    }, default=str)


@tool
async def get_related_anomalies(server_id: str, hours: int = 24) -> str:
    """
    Fetch recent Tier 2 anomaly observations for a server.
    Useful for correlating heuristic signals with a rule-based incident.
    Returns up to 10 anomalies.
    """
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = {"server_id": server_id, "last_seen_at": {"$gte": since}}

    cursor = db["log_observations"].find(query).sort("last_seen_at", -1).limit(10)
    obs = await cursor.to_list(length=10)

    result = [
        {
            "id": str(o["_id"]),
            "type": o.get("type", ""),
            "severity": o.get("severity", ""),
            "status": o.get("status", ""),
            "score": o.get("score"),
            "reasons": o.get("reasons", []),
            "occurrence_count": o.get("occurrence_count", 1),
            "last_seen_at": _safe_str(o.get("last_seen_at")),
            "log_message": (o.get("log_message", "") or "")[:200],
        }
        for o in obs
    ]
    return json.dumps(result, default=str)[:3000]


@tool
async def get_rule(rule_id: str) -> str:
    """
    Fetch a detection rule by ID, including its name, regex pattern, severity,
    action level, and linked remediation script name.
    """
    db = get_database()
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return json.dumps({"error": f"Invalid rule_id: {rule_id}"})

    rule = await db["rules"].find_one({"_id": oid})
    if not rule:
        return json.dumps({"error": "Rule not found"})

    script_name = None
    script_id = rule.get("remediation_script_id")
    if script_id:
        try:
            script = await db["scripts"].find_one({"_id": ObjectId(str(script_id))}, {"name": 1})
            if script:
                script_name = script.get("name")
        except Exception:
            pass

    return json.dumps({
        "id": str(rule["_id"]),
        "name": rule.get("name", ""),
        "pattern": rule.get("pattern", ""),
        "severity": rule.get("severity", ""),
        "action_level": rule.get("action_level"),
        "os_type": rule.get("os_type", ""),
        "description": rule.get("description", ""),
        "enabled": rule.get("enabled", True),
        "remediation_script": script_name,
    }, default=str)


@tool
async def get_anomaly(observation_id: str) -> str:
    """
    Fetch a single Tier 2 anomaly observation by ID with server hostname enrichment.
    """
    db = get_database()
    try:
        oid = ObjectId(observation_id)
    except Exception:
        return json.dumps({"error": f"Invalid observation_id: {observation_id}"})

    obs = await db["log_observations"].find_one({"_id": oid})
    if not obs:
        return json.dumps({"error": "Observation not found"})

    obs["_id"] = str(obs["_id"])

    # Enrich with hostname
    hostname = ""
    if obs.get("server_id"):
        try:
            srv = await db["servers"].find_one({"_id": ObjectId(obs["server_id"])}, {"hostname": 1})
            if srv:
                hostname = srv.get("hostname", "")
        except Exception:
            pass

    return json.dumps({
        "id": obs["_id"],
        "server_id": obs.get("server_id", ""),
        "server_hostname": hostname,
        "type": obs.get("type", ""),
        "severity": obs.get("severity", ""),
        "status": obs.get("status", ""),
        "score": obs.get("score"),
        "reasons": obs.get("reasons", []),
        "occurrence_count": obs.get("occurrence_count", 1),
        "first_seen_at": _safe_str(obs.get("first_seen_at")),
        "last_seen_at": _safe_str(obs.get("last_seen_at")),
        "log_message": (obs.get("log_message", "") or "")[:500],
    }, default=str)


@tool
async def get_pattern_history(server_id: str, pattern_hash: str) -> str:
    """
    Look up a specific log pattern's history for a server.
    Returns first/last seen timestamps and total occurrence count.
    """
    db = get_database()
    pat = await db["server_log_patterns"].find_one(
        {"server_id": server_id, "pattern_hash": pattern_hash}
    )
    if not pat:
        return json.dumps({"found": False, "pattern_hash": pattern_hash})

    return json.dumps({
        "found": True,
        "pattern_hash": pattern_hash,
        "server_id": server_id,
        "first_seen_at": _safe_str(pat.get("first_seen_at")),
        "last_seen_at": _safe_str(pat.get("last_seen_at")),
        "seen_count": pat.get("seen_count", 1),
    }, default=str)


def _parse_ts(timestamp_iso: str) -> datetime:
    """Parse ISO timestamp string to UTC-aware datetime."""
    try:
        dt = datetime.fromisoformat(timestamp_iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


@tool
async def get_logs_around(
    server_id: str,
    timestamp_iso: str,
    window_minutes: int = 3,
    limit: int = 30,
    level: Optional[str] = None,
) -> str:
    """
    Fetch log entries within ±window_minutes of the given timestamp for a server.
    Use this to reconstruct what was happening AT the time an incident/anomaly fired.
    timestamp_iso must be an ISO-8601 string (e.g. '2026-05-11T14:32:10+00:00').
    Returns up to 30 entries in chronological order.
    """
    db = get_database()
    anchor = _parse_ts(timestamp_iso)
    delta = timedelta(minutes=max(1, min(window_minutes, 60)))
    limit = min(limit, 30)
    query: dict = {
        "server_id": server_id,
        "timestamp": {"$gte": anchor - delta, "$lte": anchor + delta},
    }
    if level:
        query["level"] = level
    cursor = db["logs"].find(query).sort("timestamp", 1).limit(limit)
    logs = await cursor.to_list(length=limit)
    result = [
        {
            "timestamp": _safe_str(l.get("timestamp")),
            "level": l.get("level", ""),
            "message": (l.get("message", "") or "")[:300],
            "source": l.get("source", ""),
        }
        for l in logs
    ]
    return json.dumps({"window": f"{timestamp_iso} ±{window_minutes}min", "count": len(result), "logs": result}, default=str)[:3000]


@tool
async def get_metrics_around(
    server_id: str,
    timestamp_iso: str,
    window_minutes: int = 5,
) -> str:
    """
    Fetch CPU/RAM/disk metric snapshots within ±window_minutes of the given timestamp.
    Use this to correlate resource spikes with an incident/anomaly trigger time.
    Returns a time-series of metric points in chronological order.
    """
    from app.modules.metrics.service import MetricService
    anchor = _parse_ts(timestamp_iso)
    delta = timedelta(minutes=max(1, min(window_minutes, 60)))
    from_dt = (anchor - delta).isoformat()
    to_dt = (anchor + delta).isoformat()
    try:
        points = await MetricService().get_latest_metrics(
            server_id=server_id, limit=20, from_date=from_dt, to_date=to_dt
        )
    except Exception as e:
        return json.dumps({"error": str(e), "window": f"±{window_minutes}min"})
    result = [
        {
            "timestamp": p.get("timestamp", ""),
            "cpu_usage": p.get("cpu_usage"),
            "ram_usage": p.get("ram_usage"),
            "disk_usage": p.get("disk_usage"),
        }
        for p in (points or [])
    ]
    return json.dumps({"window": f"{timestamp_iso} ±{window_minutes}min", "count": len(result), "metrics": result}, default=str)[:3000]


@tool
async def get_incidents_around(
    server_id: str,
    timestamp_iso: str,
    window_minutes: int = 10,
    rule_id: Optional[str] = None,
) -> str:
    """
    Fetch incidents on this server that occurred within ±window_minutes of the given timestamp.
    Useful for spotting concurrent rule triggers (multi-vector attacks, correlated failures).
    """
    db = get_database()
    anchor = _parse_ts(timestamp_iso)
    delta = timedelta(minutes=max(1, min(window_minutes, 120)))
    query: dict = {
        "server_id": server_id,
        "detected_at": {"$gte": anchor - delta, "$lte": anchor + delta},
    }
    if rule_id:
        query["rule_id"] = rule_id
    cursor = db["incidents"].find(query).sort("detected_at", 1).limit(15)
    incidents = await cursor.to_list(length=15)
    result = [
        {
            "id": str(i["_id"]),
            "rule_id": str(i.get("rule_id", "")),
            "severity": i.get("severity", ""),
            "status": i.get("status", ""),
            "detected_at": _safe_str(i.get("detected_at")),
            "description": (i.get("description", "") or "")[:150],
        }
        for i in incidents
    ]
    return json.dumps({"window": f"{timestamp_iso} ±{window_minutes}min", "count": len(result), "incidents": result}, default=str)[:3000]


@tool
async def get_anomalies_around(
    server_id: str,
    timestamp_iso: str,
    window_minutes: int = 10,
) -> str:
    """
    Fetch Tier 2 anomaly observations that were active within ±window_minutes of the given timestamp.
    Use this to find heuristic signals that fired alongside a rule-based incident.
    """
    db = get_database()
    anchor = _parse_ts(timestamp_iso)
    delta = timedelta(minutes=max(1, min(window_minutes, 120)))
    query = {
        "server_id": server_id,
        "last_seen_at": {"$gte": anchor - delta, "$lte": anchor + delta},
    }
    cursor = db["log_observations"].find(query).sort("last_seen_at", 1).limit(15)
    obs = await cursor.to_list(length=15)
    result = [
        {
            "id": str(o["_id"]),
            "type": o.get("type", ""),
            "severity": o.get("severity", ""),
            "score": o.get("score"),
            "reasons": o.get("reasons", []),
            "occurrence_count": o.get("occurrence_count", 1),
            "last_seen_at": _safe_str(o.get("last_seen_at")),
            "log_message": (o.get("log_message", "") or "")[:150],
        }
        for o in obs
    ]
    return json.dumps({"window": f"{timestamp_iso} ±{window_minutes}min", "count": len(result), "anomalies": result}, default=str)[:3000]


# Convenience lists for toolset assembly
READ_TOOLS = [
    get_incident,
    get_recent_logs,
    get_related_incidents,
    get_server_metrics,
    get_related_anomalies,
    get_rule,
    get_anomaly,
    get_pattern_history,
]

# Time-anchored tools — added separately so policy.py can compose the full toolset
READ_TOOLS_ANCHORED = [
    get_logs_around,
    get_metrics_around,
    get_incidents_around,
    get_anomalies_around,
]

# Complete toolset — both now-anchored and time-anchored
ALL_READ_TOOLS = READ_TOOLS + READ_TOOLS_ANCHORED
