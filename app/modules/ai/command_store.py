"""
ai_command collection accessor.

Each row tracks the full lifecycle of one AI-suggested command:
suggestion → decision → execution → pre/post snapshots → impact analysis pointer.
"""
from datetime import datetime, timezone
from typing import List, Optional
import uuid

from bson import ObjectId

from app.core.database import get_database
from app.core.datetime_utils import utc_now


async def create_commands(
    *,
    analysis_id: str,
    run_id: str,
    source_type: str,
    source_id: str,
    server_id: str,
    suggestions: List[dict],
) -> List[str]:
    """
    Insert one ai_command row per suggestion. Returns list of new _id strings.
    """
    db = get_database()
    now = utc_now()
    docs = []
    for s in suggestions:
        docs.append({
            "analysis_id": analysis_id,
            "run_id": run_id,
            "batch_id": None,
            "source_type": source_type,
            "source_id": source_id,
            "server_id": server_id,
            "command": s.get("command", ""),
            "os_type": s.get("os_type", "linux"),
            "purpose": s.get("purpose", ""),
            "risk_level": s.get("risk_level", "medium"),
            "expected_outcome": s.get("expected_outcome", ""),
            "is_read_only": s.get("is_read_only", False),
            "status": "pending",
            "decided_at": None,
            "decided_by": None,
            "stdout": None,
            "stderr": None,
            "exit_code": None,
            "duration_ms": None,
            "executed_at": None,
            "pre_snapshot": None,
            "post_snapshot": None,
            "impact_analysis_id": None,
            "impact_verdict": None,
            "impact_summary": None,
            "error": None,
            "blocked_by_guardrail": None,
            "created_at": now,
        })
    if not docs:
        return []
    result = await db["ai_command"].insert_many(docs)
    return [str(oid) for oid in result.inserted_ids]


async def approve_commands(command_ids: List[str], decided_by: str = "operator") -> str:
    """
    Generate a batch_id, mark all rows pending→approved. Returns the batch_id.
    """
    db = get_database()
    batch_id = str(uuid.uuid4())[:12]
    now = utc_now()
    oids = [ObjectId(cid) for cid in command_ids if ObjectId.is_valid(cid)]
    if oids:
        await db["ai_command"].update_many(
            {"_id": {"$in": oids}, "status": "pending"},
            {"$set": {"status": "approved", "batch_id": batch_id, "decided_at": now, "decided_by": decided_by}},
        )
    return batch_id


async def reject_commands(command_ids: List[str], decided_by: str = "operator") -> None:
    db = get_database()
    now = utc_now()
    oids = [ObjectId(cid) for cid in command_ids if ObjectId.is_valid(cid)]
    if oids:
        await db["ai_command"].update_many(
            {"_id": {"$in": oids}, "status": "pending"},
            {"$set": {"status": "rejected", "decided_at": now, "decided_by": decided_by}},
        )


async def get_command(command_id: str) -> Optional[dict]:
    db = get_database()
    try:
        doc = await db["ai_command"].find_one({"_id": ObjectId(command_id)})
    except Exception:
        return None
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    return doc


async def get_commands_for_source(source_type: str, source_id: str) -> List[dict]:
    db = get_database()
    cursor = db["ai_command"].find(
        {"source_type": source_type, "source_id": source_id}
    ).sort("created_at", 1)
    docs = await cursor.to_list(length=100)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


async def get_commands_by_batch(batch_id: str) -> List[dict]:
    db = get_database()
    cursor = db["ai_command"].find({"batch_id": batch_id}).sort("created_at", 1)
    docs = await cursor.to_list(length=50)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


async def list_commands(
    status: Optional[str] = None,
    server_id: Optional[str] = None,
    source_id: Optional[str] = None,
    source_type: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    page: int = 1,
    page_size: int = 25,
) -> dict:
    from datetime import datetime
    db = get_database()
    query: dict = {}
    if status and status != "all":
        query["status"] = status
    if server_id:
        query["server_id"] = server_id
    if source_id:
        query["source_id"] = source_id
    if source_type and source_type != "all":
        query["source_type"] = source_type
    date_range: dict = {}
    if from_date:
        try:
            date_range["$gte"] = datetime.fromisoformat(from_date.replace("Z", "+00:00"))
        except Exception:
            pass
    if to_date:
        try:
            date_range["$lte"] = datetime.fromisoformat(to_date.replace("Z", "+00:00"))
        except Exception:
            pass
    if date_range:
        query["created_at"] = date_range

    total = await db["ai_command"].count_documents(query)
    skip = (page - 1) * page_size
    cursor = db["ai_command"].find(query).sort("created_at", -1).skip(skip).limit(page_size)
    docs = await cursor.to_list(length=page_size)
    for d in docs:
        d["_id"] = str(d["_id"])

    # Batch-enrich with server hostname (one query for all unique server_ids on this page)
    server_ids = list({d["server_id"] for d in docs if d.get("server_id")})
    if server_ids:
        try:
            srv_cursor = db["servers"].find(
                {"_id": {"$in": [ObjectId(sid) for sid in server_ids if ObjectId.is_valid(sid)]}},
                {"hostname": 1},
            )
            srv_docs = await srv_cursor.to_list(length=len(server_ids))
            hostname_map = {str(s["_id"]): s.get("hostname", "") for s in srv_docs}
            for d in docs:
                d["server_hostname"] = hostname_map.get(d.get("server_id", ""), "")
        except Exception:
            pass

    return {"total": total, "page": page, "page_size": page_size, "results": docs}


async def pending_count() -> int:
    db = get_database()
    return await db["ai_command"].count_documents({"status": "pending"})


_RETRYABLE_STATUSES = {"failed", "blocked"}


async def retry_command(command_id: str) -> str:
    """
    Clone a failed/blocked command into a fresh pending row for re-execution.
    Returns the new command's _id string.
    """
    db = get_database()
    try:
        src = await db["ai_command"].find_one({"_id": ObjectId(command_id)})
    except Exception:
        raise ValueError("invalid command_id")
    if not src:
        raise ValueError("command not found")

    status = src.get("status", "")
    exit_code = src.get("exit_code")
    is_retryable = (
        status in _RETRYABLE_STATUSES
        or (status == "completed" and exit_code not in (0, None))
    )
    if not is_retryable:
        raise ValueError(f"command status '{status}' is not retryable")

    now = utc_now()
    new_doc = {k: v for k, v in src.items() if k != "_id"}
    new_doc.update({
        "status": "pending",
        "batch_id": None,
        "decided_at": None,
        "decided_by": None,
        "stdout": None,
        "stderr": None,
        "exit_code": None,
        "duration_ms": None,
        "executed_at": None,
        "pre_snapshot": None,
        "post_snapshot": None,
        "impact_analysis_id": None,
        "impact_verdict": None,
        "impact_summary": None,
        "error": None,
        "blocked_by_guardrail": None,
        "retry_of": command_id,
        "created_at": now,
    })
    result = await db["ai_command"].insert_one(new_doc)
    return str(result.inserted_id)
