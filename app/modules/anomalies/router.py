from app.core.constants import Collections, UserRole
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from app.core.errors import http_error
from app.core.auth import CurrentUser, ensure_server_access, get_current_user, require_role

from app.modules.anomalies.schemas import LogObservationListResponse, LogObservationResponse
from app.modules.anomalies.service import AnomaliesService

router = APIRouter()
service = AnomaliesService()
_operator = require_role(UserRole.OPERATOR.value)


@router.get("/stats")
async def get_anomaly_stats(user: CurrentUser = Depends(get_current_user)):
    """
    Dashboard aggregate: total / pending / dismissed / promoted counts.
    Scoped to the principal's servers (admins see all).
    Must be above /{observation_id}.
    """
    return await service.stats(allowed_server_ids=None if user.is_admin else user.server_ids)


@router.get("/", response_model=LogObservationListResponse)
async def list_observations(
    server_id: Optional[str] = Query(None, description="Filter by server"),
    status: Optional[str] = Query(None, description="pending_review | dismissed | promoted_to_incident | all"),
    severity: Optional[str] = Query(None, description="low | medium | high | all"),
    type: Optional[str] = Query(None, description="log | volume | all"),
    from_date: Optional[str] = Query(None, description="ISO datetime — filter on last_seen_at >= this time"),
    to_date: Optional[str] = Query(None, description="ISO datetime — filter on last_seen_at <= this time"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    user: CurrentUser = Depends(get_current_user),
):
    """List anomaly observations, newest first. Date range applies on `last_seen_at`. Scoped to the principal's servers."""
    return await service.list(
        page=page,
        page_size=page_size,
        server_id=server_id,
        status=status,
        severity=severity,
        type_=type,
        from_date=from_date,
        to_date=to_date,
        allowed_server_ids=None if user.is_admin else user.server_ids,
    )


@router.get("/{observation_id}", response_model=LogObservationResponse)
async def get_observation(observation_id: str, user: CurrentUser = Depends(get_current_user)):
    """Get one anomaly observation with detail-page enrichment."""
    observation = await service.get_by_id(observation_id)
    if not observation:
        raise HTTPException(status_code=404, detail="Observation not found")
    ensure_server_access(user, str(observation.get("server_id")))
    return observation


@router.post("/{observation_id}/analyze")
async def analyze_observation(observation_id: str, user: CurrentUser = Depends(_operator)):
    """
    Run the LangGraph anomaly triage agent on a Tier 2 observation.
    Saves ai_analysis + promotion_recommendation to the observation document.
    """
    from app.modules.ai.anomaly_graph import run_anomaly_triage
    from app.core.database import get_database
    from bson import ObjectId

    db = get_database()
    try:
        oid = ObjectId(observation_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    obs = await db[Collections.LOG_OBSERVATIONS].find_one({"_id": oid}, {"server_id": 1})
    if not obs:
        raise HTTPException(status_code=404, detail="Observation not found")
    ensure_server_access(user, str(obs.get("server_id")))

    await db[Collections.LOG_OBSERVATIONS].update_one(
        {"_id": oid},
        {"$set": {"ai_analysis_in_progress": True}},
    )

    try:
        result = await run_anomaly_triage(observation_id)
    except Exception as exc:
        await db[Collections.LOG_OBSERVATIONS].update_one(
            {"_id": oid},
            {"$set": {"ai_analysis_in_progress": False}},
        )
        raise http_error(503, "AI triage failed — please try again.", exc, "anomaly triage")

    # Keep legacy fields for backward compat
    await db[Collections.LOG_OBSERVATIONS].update_one(
        {"_id": oid},
        {"$set": {
            "ai_analysis": result["markdown"],
            "ai_promotion_recommendation": result["promotion_recommendation"],
            "ai_analyzed_at": result["analyzed_at"],
            "ai_analysis_in_progress": False,
            "ai_manual_commands": result["manual_commands"],
        }},
    )

    return {
        "status": "success",
        "observation_id": observation_id,
        "analysis_id": result["analysis_id"],
        "run_id": result["run_id"],
        "ai_analysis": result["markdown"],
        "promotion_recommendation": result["promotion_recommendation"],
        "suggested_command_ids": result["suggested_command_ids"],
        "manual_commands": result["manual_commands"],
        "pending_action_ids": result["pending_action_ids"],
        "confidence": result["confidence"],
        "analyzed_at": result["analyzed_at"],
    }


@router.patch("/{observation_id}/dismiss")
async def dismiss_observation(observation_id: str, user: CurrentUser = Depends(_operator)):
    """Mark a pending observation as dismissed (false positive / not interesting)."""
    existing = await service.get_by_id(observation_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Observation not found")
    ensure_server_access(user, str(existing.get("server_id")))
    ok = await service.dismiss(observation_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail="Observation not found or already reviewed",
        )
    return {"status": "dismissed", "observation_id": observation_id}


@router.post("/{observation_id}/promote")
async def promote_observation(observation_id: str, user: CurrentUser = Depends(_operator)):
    """
    Promote a pending observation to a real incident. The observation
    transitions to PROMOTED_TO_INCIDENT and a new incident is created with
    rule_id="anomaly:promoted".
    """
    existing = await service.get_by_id(observation_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Observation not found")
    ensure_server_access(user, str(existing.get("server_id")))
    incident_id = await service.promote_to_incident(observation_id)
    if not incident_id:
        raise HTTPException(
            status_code=404,
            detail="Observation not found, already reviewed, or invalid id",
        )
    return {
        "status": "promoted",
        "observation_id": observation_id,
        "incident_id": incident_id,
    }


@router.post("/{observation_id}/auto-promote")
async def auto_promote_observation(observation_id: str, user: CurrentUser = Depends(_operator)):
    """
    Attempt auto-promotion: promotes only if severity==high, occurrence_count>=3,
    and the fingerprint is not in the dismissed suppression list.
    Returns 409 if conditions are not met.
    Does NOT require ANOMALY_AUTO_PROMOTE env var — that flag only controls
    the background auto-promotion. This endpoint always tries.
    """
    obs = await service.get_by_id(observation_id)
    if not obs:
        raise HTTPException(status_code=404, detail="Observation not found")
    ensure_server_access(user, str(obs.get("server_id")))

    promoted = await service.maybe_auto_promote(
        observation_id, obs.get("server_id", ""), force=True
    )
    if not promoted:
        raise HTTPException(
            status_code=409,
            detail="Auto-promotion conditions not met (severity<high, count<3, or suppressed)",
        )
    return {"status": "auto_promoted", "observation_id": observation_id}
