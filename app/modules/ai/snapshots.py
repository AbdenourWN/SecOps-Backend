"""
Snapshot helpers shared between the operator-approved command path
(`execution_graph.py`) and the automated script review path (`script_review.py`).

`capture_snapshot(server_id, anchor)` returns the same rich dict shape used by
both: legacy fields (`metrics`, `log_tail`, `open_incidents_count`, `timestamp`)
plus the impact-agent fields (`anchor`, `server_state`, `metrics_window`).

`fetch_review_logs(server_id, source_anchor)` returns two ES log slices
deduplicated by `_id` — same shape as the impact agent's input. Reused so both
review paths get logs at the alert moment + the freshest logs after settling.
"""
from app.core.constants import Collections
import asyncio
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId

from app.core.database import get_database
from app.modules.ai.context_builder import _fetch_metrics_window


async def capture_snapshot(server_id: str, anchor: datetime) -> dict:
    """
    Metrics + server-state snapshot anchored on a specific time.

    Returns both the legacy single-metric shape (used by frontend MetricRow
    display) and the richer metrics_window for the LLM. Logs are deliberately
    NOT here — they are captured separately via `fetch_review_logs` so the
    "at source" slice can be anchored on the *source alert* time, not the
    snapshot time.
    """
    db = get_database()

    server_state: dict = {}
    open_incidents_count = 0
    try:
        srv = await db[Collections.SERVERS].find_one(
            {"_id": ObjectId(server_id)},
            {"hostname": 1, "is_online": 1, "status": 1, "last_metrics": 1},
        )
        if srv:
            lm = srv.get("last_metrics") or {}
            server_state = {
                "hostname": srv.get("hostname", ""),
                "is_online": srv.get("is_online", False),
                "status": srv.get("status", ""),
                "last_metrics_cached": {
                    "cpu_usage": lm.get("cpu_usage"),
                    "ram_usage": lm.get("ram_usage"),
                    "disk_usage": lm.get("disk_usage"),
                    "collected_at": str(lm.get("collected_at", "")),
                },
            }
        open_incidents_count = await db[Collections.INCIDENTS].count_documents(
            {"server_id": server_id, "status": {"$in": ["open", "verifying"]}}
        )
    except Exception:
        pass

    metrics_window = await _fetch_metrics_window(server_id, anchor, window_minutes=5)

    if metrics_window:
        rep = metrics_window[-1]
        single = {
            "cpu_usage": rep.get("cpu"),
            "ram_usage": rep.get("ram"),
            "disk_usage": rep.get("disk"),
            "collected_at": rep.get("t", ""),
        }
    else:
        single = (server_state.get("last_metrics_cached") or {}).copy()

    return {
        # Legacy shape — kept so the CommandDetailModal MetricRow keeps rendering
        "metrics": single,
        "log_tail": [],
        "open_incidents_count": open_incidents_count,
        "timestamp": anchor.isoformat(),
        # Rich fields used by the impact/review agent
        "anchor": anchor.isoformat(),
        "server_state": server_state,
        "metrics_window": metrics_window,
    }


async def fetch_review_logs(server_id: str, source_anchor: datetime) -> dict:
    """
    Two log slices from Elasticsearch:
      - at_source: 5 lines immediately before + 5 immediately after `source_anchor`
                   (in chronological order)
      - latest:    10 newest log lines for this server, deduplicated against
                   at_source by ES `_id` (no entry appears in both)
    """
    from app.core.elasticsearch import get_elasticsearch
    es = get_elasticsearch()
    if not es:
        return {"at_source": [], "latest": []}

    async def _search(body: dict) -> list:
        try:
            res = await es.search(index="secops-logs-*", body=body)
            out = []
            for h in res["hits"]["hits"]:
                src = h["_source"]
                out.append({
                    "_id": h["_id"],
                    "t": src.get("timestamp", ""),
                    "level": src.get("level", ""),
                    "msg": (src.get("message", "") or "")[:250],
                    "src": src.get("source", ""),
                })
            return out
        except Exception:
            return []

    if source_anchor.tzinfo is None:
        source_anchor = source_anchor.replace(tzinfo=timezone.utc)
    anchor_iso = source_anchor.isoformat()
    before_body = {
        "query": {"bool": {"filter": [
            {"term": {"server_id": server_id}},
            {"range": {"timestamp": {"lte": anchor_iso}}},
        ]}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 5,
        "_source": ["timestamp", "level", "message", "source"],
    }
    after_body = {
        "query": {"bool": {"filter": [
            {"term": {"server_id": server_id}},
            {"range": {"timestamp": {"gt": anchor_iso}}},
        ]}},
        "sort": [{"timestamp": {"order": "asc"}}],
        "size": 5,
        "_source": ["timestamp", "level", "message", "source"],
    }
    latest_body = {
        "query": {"term": {"server_id": server_id}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 10,
        "_source": ["timestamp", "level", "message", "source"],
    }

    before, after, latest = await asyncio.gather(
        _search(before_body), _search(after_body), _search(latest_body),
    )

    at_source = list(reversed(before)) + after
    at_source_ids = {l["_id"] for l in at_source}
    latest_dedup = [l for l in latest if l["_id"] not in at_source_ids]

    return {"at_source": at_source, "latest": latest_dedup}
