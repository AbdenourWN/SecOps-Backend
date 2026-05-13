"""
Mutation tools for the AI triage agent.

These tools are NOT added to the agent toolset directly. Instead, policy.py
wraps them according to the server's ai_autonomy_level:

  read_only → tools omitted entirely
  suggest   → tools write a pending action to `ai_actions`; no execution
              (operator approves/rejects on the AI Actions page)
"""
import json
from typing import Optional

from langchain_core.tools import tool

from app.core.database import get_database
from app.core.datetime_utils import utc_now


# ── Raw executors (called by router when an operator approves a queued action) ──

async def _execute_dismiss_anomaly(observation_id: str, reason: str) -> dict:
    from app.modules.anomalies.service import AnomaliesService
    ok = await AnomaliesService().dismiss(observation_id)
    return {"executed": ok, "observation_id": observation_id, "action": "dismiss_anomaly"}


async def _execute_promote_anomaly(observation_id: str) -> dict:
    from app.modules.anomalies.service import AnomaliesService
    from bson import ObjectId
    db = get_database()
    try:
        oid = ObjectId(observation_id)
    except Exception:
        return {"executed": False, "error": "Invalid observation_id"}
    obs = await db["log_observations"].find_one({"_id": oid}, {"server_id": 1})
    server_id = str(obs["server_id"]) if obs else ""
    incident_id = await AnomaliesService().maybe_auto_promote(observation_id, server_id, force=True)
    return {
        "executed": bool(incident_id),
        "observation_id": observation_id,
        "incident_id": incident_id,
        "action": "promote_anomaly",
    }


async def _execute_mark_incident_false_positive(incident_id: str, reason: str) -> dict:
    from bson import ObjectId
    db = get_database()
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return {"executed": False, "error": "Invalid incident_id"}
    result = await db["incidents"].update_one(
        {"_id": oid, "status": {"$nin": ["false_positive", "resolved"]}},
        {"$set": {"status": "false_positive", "ai_false_positive_reason": reason, "updated_at": utc_now()}},
    )
    return {"executed": result.modified_count > 0, "incident_id": incident_id, "action": "mark_false_positive"}


# ── Pending-action queue helper (suggest level) ──────────────────────────────

async def _queue_action(action_type: str, payload: dict, run_id: str) -> str:
    db = get_database()
    doc = {
        "action_type": action_type,
        "payload": payload,
        "run_id": run_id,
        "status": "pending",
        "created_at": utc_now(),
        "decided_at": None,
        "decided_by": None,
    }
    result = await db["ai_actions"].insert_one(doc)
    return str(result.inserted_id)


# ── Tool factories — called by policy.py to produce level-appropriate tools ──

def make_dismiss_anomaly_tool(level: str, run_id: str) -> Optional[object]:
    if level == "suggest":
        @tool
        async def dismiss_anomaly(observation_id: str, reason: str) -> str:
            """
            Dismiss a Tier 2 anomaly observation (mark as not interesting / false positive).
            Provide the observation_id and a brief reason string.
            """
            action_id = await _queue_action(
                "dismiss_anomaly",
                {"observation_id": observation_id, "reason": reason},
                run_id,
            )
            return json.dumps({"queued": True, "pending_action_id": action_id, "message": "Dismiss queued for operator approval"})
        return dismiss_anomaly
    return None


def make_promote_anomaly_tool(level: str, run_id: str) -> Optional[object]:
    if level == "suggest":
        @tool
        async def promote_anomaly(observation_id: str) -> str:
            """
            Promote a Tier 2 anomaly observation to a real incident.
            Use when the anomaly shows strong signs of a real security threat.
            """
            action_id = await _queue_action("promote_anomaly", {"observation_id": observation_id}, run_id)
            return json.dumps({"queued": True, "pending_action_id": action_id, "message": "Promotion queued for operator approval"})
        return promote_anomaly
    return None


def make_mark_false_positive_tool(level: str, run_id: str) -> Optional[object]:
    if level == "suggest":
        @tool
        async def mark_incident_false_positive(incident_id: str, reason: str) -> str:
            """
            Mark an incident as a false positive. Use when evidence clearly shows
            the alert is benign. Provide a short reason explaining why.
            """
            action_id = await _queue_action(
                "mark_incident_false_positive",
                {"incident_id": incident_id, "reason": reason},
                run_id,
            )
            return json.dumps({"queued": True, "pending_action_id": action_id, "message": "False-positive flag queued for operator approval"})
        return mark_incident_false_positive
    return None
