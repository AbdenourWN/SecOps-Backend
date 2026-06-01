"""
Small shared helpers for the Mongo data layer.

Extracted to remove copy-paste that had accumulated across the list/query
endpoints (AI actions/analyses/commands, automation history, dashboard). Each
helper reproduces the exact logic that previously lived inline — no behavior
change, just one definition instead of many.
"""
from datetime import datetime
from typing import Optional

from bson import ObjectId

from app.core.constants import Collections


def safe_object_id(value: Optional[str]) -> Optional[ObjectId]:
    """Return ObjectId(value), or None if it is missing / not a valid ObjectId."""
    if value and ObjectId.is_valid(value):
        return ObjectId(value)
    return None


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 string (tolerating a trailing 'Z'); None on empty/invalid."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def build_date_range_query(from_date: Optional[str], to_date: Optional[str]) -> dict:
    """
    Build a Mongo range sub-document from ISO strings. Returns {} when neither
    bound parses, so callers can write:

        rng = build_date_range_query(from_date, to_date)
        if rng:
            query["created_at"] = rng
    """
    rng: dict = {}
    start = parse_iso(from_date)
    end = parse_iso(to_date)
    if start is not None:
        rng["$gte"] = start
    if end is not None:
        rng["$lte"] = end
    return rng


async def enrich_with_server_hostname(
    docs: list[dict],
    db,
    *,
    id_field: str = "server_id",
    out_field: str = "server_hostname",
) -> list[dict]:
    """
    Batch-set `out_field` on each doc from the `servers` collection in one query
    (keyed by the unique `id_field` values on the page). Best-effort: on any DB
    error the docs are returned unchanged. Mutates and returns `docs`.
    """
    server_ids = list({d.get(id_field) for d in docs if d.get(id_field)})
    if not server_ids:
        return docs
    try:
        oids = [oid for oid in (safe_object_id(s) for s in server_ids) if oid is not None]
        cursor = db[Collections.SERVERS].find({"_id": {"$in": oids}}, {"hostname": 1})
        srv_docs = await cursor.to_list(length=len(server_ids))
        hostname_map = {str(s["_id"]): s.get("hostname", "") for s in srv_docs}
        for d in docs:
            d[out_field] = hostname_map.get(d.get(id_field, ""), "")
    except Exception:
        pass
    return docs
