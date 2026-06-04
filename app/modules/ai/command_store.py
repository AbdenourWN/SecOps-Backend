"""
ai_command collection accessor.

Each row tracks the full lifecycle of one AI-suggested command:
suggestion → decision → execution → pre/post snapshots → impact analysis pointer.
"""
from app.core.constants import Collections, CommandStatus, OSType, RiskLevel
from app.core.db_utils import build_date_range_query, enrich_with_server_hostname
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
            "os_type": s.get("os_type", OSType.LINUX),
            "purpose": s.get("purpose", ""),
            "risk_level": s.get("risk_level", RiskLevel.MEDIUM),
            "expected_outcome": s.get("expected_outcome", ""),
            "is_read_only": s.get("is_read_only", False),
            "status": CommandStatus.PENDING,
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
    result = await db[Collections.AI_COMMAND].insert_many(docs)
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
        await db[Collections.AI_COMMAND].update_many(
            {"_id": {"$in": oids}, "status": CommandStatus.PENDING},
            {"$set": {"status": CommandStatus.APPROVED, "batch_id": batch_id, "decided_at": now, "decided_by": decided_by}},
        )
    return batch_id


async def reject_commands(command_ids: List[str], decided_by: str = "operator") -> None:
    db = get_database()
    now = utc_now()
    oids = [ObjectId(cid) for cid in command_ids if ObjectId.is_valid(cid)]
    if oids:
        await db[Collections.AI_COMMAND].update_many(
            {"_id": {"$in": oids}, "status": CommandStatus.PENDING},
            {"$set": {"status": CommandStatus.REJECTED, "decided_at": now, "decided_by": decided_by}},
        )


async def get_command(command_id: str) -> Optional[dict]:
    db = get_database()
    try:
        doc = await db[Collections.AI_COMMAND].find_one({"_id": ObjectId(command_id)})
    except Exception:
        return None
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    return doc


async def get_commands_for_source(source_type: str, source_id: str) -> List[dict]:
    db = get_database()
    cursor = db[Collections.AI_COMMAND].find(
        {"source_type": source_type, "source_id": source_id}
    ).sort("created_at", 1)
    docs = await cursor.to_list(length=100)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


async def get_commands_by_batch(batch_id: str) -> List[dict]:
    db = get_database()
    cursor = db[Collections.AI_COMMAND].find({"batch_id": batch_id}).sort("created_at", 1)
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
    allowed_server_ids=None,
) -> dict:
    from app.core.db_utils import apply_server_scope
    db = get_database()
    query: dict = {}
    if status and status != "all":
        query["status"] = status
    apply_server_scope(query, server_id, allowed_server_ids)
    if source_id:
        query["source_id"] = source_id
    if source_type and source_type != "all":
        query["source_type"] = source_type
    date_range = build_date_range_query(from_date, to_date)
    if date_range:
        query["created_at"] = date_range

    total = await db[Collections.AI_COMMAND].count_documents(query)
    skip = (page - 1) * page_size
    cursor = db[Collections.AI_COMMAND].find(query).sort("created_at", -1).skip(skip).limit(page_size)
    docs = await cursor.to_list(length=page_size)
    for d in docs:
        d["_id"] = str(d["_id"])

    # Batch-enrich with server hostname (one query for all unique server_ids on this page)
    await enrich_with_server_hostname(docs, db)

    return {"total": total, "page": page, "page_size": page_size, "results": docs}


async def pending_count() -> int:
    db = get_database()
    return await db[Collections.AI_COMMAND].count_documents({"status": CommandStatus.PENDING})


_RETRYABLE_STATUSES = {CommandStatus.FAILED, CommandStatus.BLOCKED}


async def retry_command(command_id: str) -> str:
    """
    Clone a failed/blocked command into a fresh pending row for re-execution.
    Returns the new command's _id string.
    """
    db = get_database()
    try:
        src = await db[Collections.AI_COMMAND].find_one({"_id": ObjectId(command_id)})
    except Exception:
        raise ValueError("invalid command_id")
    if not src:
        raise ValueError("command not found")

    status = src.get("status", "")
    exit_code = src.get("exit_code")
    is_retryable = (
        status in _RETRYABLE_STATUSES
        or (status == CommandStatus.COMPLETED and exit_code not in (0, None))
    )
    if not is_retryable:
        raise ValueError(f"command status '{status}' is not retryable")

    now = utc_now()
    new_doc = {k: v for k, v in src.items() if k != "_id"}
    new_doc.update({
        "status": CommandStatus.PENDING,
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
    result = await db[Collections.AI_COMMAND].insert_one(new_doc)
    return str(result.inserted_id)
