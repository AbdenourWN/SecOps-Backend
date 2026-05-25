from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.modules.anomalies.schemas import LogObservationListResponse, LogObservationResponse
from app.modules.anomalies.service import AnomaliesService

router = APIRouter()
service = AnomaliesService()


@router.get("/stats")
async def get_anomaly_stats():
    """
    Dashboard aggregate: total / pending / dismissed / promoted counts.
    Must be above /{observation_id}.
    """
    return await service.stats()


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
):
    """List anomaly observations, newest first. Date range applies on `last_seen_at`."""
    return await service.list(
        page=page,
        page_size=page_size,
        server_id=server_id,
        status=status,
        severity=severity,
        type_=type,
        from_date=from_date,
        to_date=to_date,
    )


@router.get("/{observation_id}", response_model=LogObservationResponse)
async def get_observation(observation_id: str):
    """Get one anomaly observation with detail-page enrichment."""
    observation = await service.get_by_id(observation_id)
    if not observation:
        raise HTTPException(status_code=404, detail="Observation not found")
    return observation


@router.post("/{observation_id}/analyze")
async def analyze_observation(observation_id: str):
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

    if not await db["log_observations"].find_one({"_id": oid}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Observation not found")

    await db["log_observations"].update_one(
        {"_id": oid},
        {"$set": {"ai_analysis_in_progress": True}},
    )

    try:
        result = await run_anomaly_triage(observation_id)
    except Exception as exc:
        await db["log_observations"].update_one(
            {"_id": oid},
            {"$set": {"ai_analysis_in_progress": False}},
        )
        raise HTTPException(status_code=503, detail=f"AI triage failed: {exc}")

    # Keep legacy fields for backward compat
    await db["log_observations"].update_one(
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
async def dismiss_observation(observation_id: str):
    """Mark a pending observation as dismissed (false positive / not interesting)."""
    ok = await service.dismiss(observation_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail="Observation not found or already reviewed",
        )
    return {"status": "dismissed", "observation_id": observation_id}


@router.post("/{observation_id}/promote")
async def promote_observation(observation_id: str):
    """
    Promote a pending observation to a real incident. The observation
    transitions to PROMOTED_TO_INCIDENT and a new incident is created with
    rule_id="anomaly:promoted".
    """
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
async def auto_promote_observation(observation_id: str):
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

    promoted = await service.maybe_auto_promote(
        observation_id, obs.get("server_id", ""), force=True
    )
    if not promoted:
        raise HTTPException(
            status_code=409,
            detail="Auto-promotion conditions not met (severity<high, count<3, or suppressed)",
        )
    return {"status": "auto_promoted", "observation_id": observation_id}
