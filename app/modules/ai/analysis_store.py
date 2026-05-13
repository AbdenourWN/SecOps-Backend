"""
ai_analysis collection accessor.

Every AI-generated analysis (incident_triage, anomaly_triage, server_overview,
script_execution_review, command_impact) is stored here. Source documents
keep a denormalized pointer (ai_analysis_latest_id) + count for fast display.
"""
from datetime import datetime, timezone
from typing import List, Optional
import uuid

from bson import ObjectId

from app.core.database import get_database
from app.core.datetime_utils import utc_now


async def save_analysis(
    *,
    run_id: str,
    analysis_type: str,
    source_type: str,
    source_id: str,
    server_id: str,
    summary: str,
    markdown: str,
    confidence: float,
    structured: dict,
    anchored_at: datetime,
    window_minutes: int,
    llm_provider: str,
    llm_model: str,
) -> str:
    """
    Insert one ai_analysis row and update the source document's pointer fields.
    Returns the new analysis _id as a string.
    """
    db = get_database()
    now = utc_now()
    doc = {
        "run_id": run_id,
        "analysis_type": analysis_type,
        "source_type": source_type,
        "source_id": source_id,
        "server_id": server_id,
        "summary": summary,
        "markdown": markdown,
        "confidence": confidence,
        "structured": structured,
        "anchored_at": anchored_at if anchored_at.tzinfo else anchored_at.replace(tzinfo=timezone.utc),
        "window_minutes": window_minutes,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "created_at": now,
    }
    result = await db["ai_analysis"].insert_one(doc)
    analysis_id = str(result.inserted_id)

    # Denormalize pointer + count onto the source document
    source_collection = _source_collection(source_type)
    if source_collection:
        try:
            await db[source_collection].update_one(
                {"_id": ObjectId(source_id)},
                {
                    "$set": {"ai_analysis_latest_id": analysis_id},
                    "$inc": {"ai_analysis_count": 1},
                },
            )
        except Exception:
            pass  # non-critical; main row is already written

    return analysis_id


async def get_analysis_by_id(analysis_id: str) -> Optional[dict]:
    db = get_database()
    try:
        doc = await db["ai_analysis"].find_one({"_id": ObjectId(analysis_id)})
    except Exception:
        return None
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    return doc


async def list_analyses_for_source(
    source_type: str,
    source_id: str,
    analysis_type: Optional[str] = None,
    limit: int = 20,
) -> List[dict]:
    db = get_database()
    query: dict = {"source_type": source_type, "source_id": source_id}
    if analysis_type:
        query["analysis_type"] = analysis_type
    cursor = db["ai_analysis"].find(query).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


async def list_server_analyses(
    server_id: str,
    analysis_type: Optional[str] = None,
    limit: int = 20,
) -> List[dict]:
    db = get_database()
    query: dict = {"server_id": server_id}
    if analysis_type:
        query["analysis_type"] = analysis_type
    cursor = db["ai_analysis"].find(query).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


def _source_collection(source_type: str) -> Optional[str]:
    return {
        "incident": "incidents",
        "anomaly": "log_observations",
        "server": "servers",
        "automation_log": "automation_logs",
        "command": "ai_command",
    }.get(source_type)
