from fastapi import APIRouter, HTTPException, Query, Depends
from app.core.errors import http_error
from typing import List, Optional
from app.modules.logs.service import LogService
from app.modules.logs.schemas import (
    LogResponse,
    LogSourceCreate,
    LogSourceInDB,
    LogSourceUpdate,
)
from app.modules.logs.file_watcher import FileWatcherService
from app.core.elasticsearch import get_elasticsearch
from app.core.auth import CurrentUser, ensure_server_access, get_current_user, require_role
from app.core.constants import UserRole

watcher_service = FileWatcherService()


router = APIRouter()
service = LogService()
_operator = require_role(UserRole.OPERATOR.value)
_admin = require_role(UserRole.ADMIN.value)


@router.get("/search")
async def search_logs(
    q: Optional[str] = Query(None, description="Full-text search query (e.g., 'failed password')"),
    server_id: Optional[str] = Query(None, description="Filter by server ID"),
    level: Optional[str] = Query(None, description="Filter by level: ERROR, WARNING, INFO"),
    from_date: Optional[str] = Query(None, description="Start date (ISO format: 2026-03-01)"),
    to_date: Optional[str] = Query(None, description="End date (ISO format: 2026-03-31)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: CurrentUser = Depends(get_current_user),
):
    """
    Full-text log search powered by Elasticsearch.

    HOW THIS WORKS:
    - 'q' searches the 'message' field using ES full-text analysis
      (e.g., "failed password" finds "Failed Password for root from...")
    - Filters (server_id, level, date range) use exact matching
    - Results sorted newest-first
    - Scoped to the principal's servers (admin sees all).
    """
    es = get_elasticsearch()
    if not es:
        raise HTTPException(status_code=503, detail="Elasticsearch is not available")

    # Build the query dynamically
    must_clauses = []
    filter_clauses = []

    # Full-text search on message field
    if q:
        must_clauses.append({"match": {"message": q}})

    # Exact match filters + RBAC server scoping
    if server_id:
        ensure_server_access(user, server_id)
        filter_clauses.append({"term": {"server_id": server_id}})
    elif not user.is_admin:
        # No explicit server filter → restrict to the principal's assigned servers.
        filter_clauses.append({"terms": {"server_id": user.server_ids}})
    if level:
        filter_clauses.append({"term": {"level": level.upper()}})

    # Date range filter
    if from_date or to_date:
        date_range = {}
        if from_date:
            date_range["gte"] = from_date
        if to_date:
            date_range["lte"] = to_date
        filter_clauses.append({"range": {"timestamp": date_range}})

    # Combine into bool query
    bool_query = {}
    if must_clauses:
        bool_query["must"] = must_clauses
    if filter_clauses:
        bool_query["filter"] = filter_clauses

    # If nothing specified, match all
    query = {"bool": bool_query} if bool_query else {"match_all": {}}

    try:
        result = await es.search(
            index="secops-logs-*",
            body={
                "query": query,
                "sort": [{"timestamp": {"order": "desc"}}],
                "from": skip,
                "size": limit,
            }
        )

        total = result["hits"]["total"]["value"]
        logs = []
        for hit in result["hits"]["hits"]:
            doc = hit["_source"]
            doc["_id"] = hit["_id"]
            doc["_score"] = hit.get("_score")  # Relevance score
            logs.append(doc)

        return {
            "total": total,
            "showing": len(logs),
            "skip": skip,
            "limit": limit,
            "results": logs,
        }
    except Exception as e:
        raise http_error(500, "Log search failed — please try again.", e, "log search")


@router.post("/collect/{server_id}")
async def trigger_log_collection(server_id: str, user: CurrentUser = Depends(_operator)):
    """
    Manually triggers log collection.
    Useful for testing before we build the Scheduler.
    """
    ensure_server_access(user, server_id)
    result = await service.collect_logs_from_server(server_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Log sources CRUD
# IMPORTANT: every /sources* route MUST be declared above /{server_id} below,
# otherwise FastAPI will match "sources" as a server_id and shadow these.
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/sources", response_model=list)
async def list_log_sources(server_id: Optional[str] = Query(None)):
    """
    List log sources. When server_id is provided, returns only that server's
    sources (used by the per-server settings tab).
    """
    if server_id:
        return await watcher_service.get_sources_by_server(server_id)
    sources = await watcher_service.get_all_sources()
    for s in sources:
        s["_id"] = str(s["_id"])
    return sources


@router.post("/sources", response_model=dict)
async def add_log_source(source: LogSourceCreate, user: CurrentUser = Depends(_admin)):
    """
    Tell the system to watch a specific file (e.g. /var/log/nginx/access.log)
    """
    id = await watcher_service.create_source(source)
    return {"status": "success", "id": id}


@router.post("/sources/poll")
async def force_poll_sources(user: CurrentUser = Depends(_admin)):
    """
    Manually trigger file polling (for testing)
    """
    sources = await watcher_service.get_all_sources()
    for source in sources:
        await watcher_service.process_file_source(source)
    return {"status": "success", "processed": len(sources)}


@router.put("/sources/{source_id}", response_model=dict)
async def update_log_source(source_id: str, updates: LogSourceUpdate, user: CurrentUser = Depends(_admin)):
    """
    Patch an existing log source. Changing file_path resets the bookmark
    state so the new file is read from offset 0 on the next poll.
    """
    payload = updates.model_dump(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=400, detail="No fields to update")

    ok = await watcher_service.update_source(source_id, payload)
    if not ok:
        raise HTTPException(status_code=404, detail="Log source not found")
    return {"status": "success"}


@router.delete("/sources/{source_id}", response_model=dict)
async def delete_log_source(source_id: str, user: CurrentUser = Depends(_admin)):
    ok = await watcher_service.delete_source(source_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Log source not found")
    return {"status": "success"}


@router.get("/{server_id}")
async def get_server_logs(server_id: str, limit: int = 50, user: CurrentUser = Depends(get_current_user)):
    """
    Fetch the latest logs from Elasticsearch for a specific server.
    """
    ensure_server_access(user, server_id)
    return await service.get_logs(server_id, limit)