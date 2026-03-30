from fastapi import APIRouter, HTTPException
from app.modules.analysis.ai_service import AIService
from app.modules.analysis.schemas import DetectionRule
from app.core.database import get_database
from bson import ObjectId

router = APIRouter()
ai_service = AIService()


# ── Rules CRUD ──

@router.get("/rules")
async def list_rules():
    db = get_database()
    rules = await db["rules"].find().to_list(length=200)
    for r in rules:
        r["_id"] = str(r["_id"])
        if "remediation_script_id" in r and r["remediation_script_id"]:
            r["remediation_script_id"] = str(r["remediation_script_id"])
    return rules

@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    db = get_database()
    try:
        rule = await db["rules"].find_one({"_id": ObjectId(rule_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule["_id"] = str(rule["_id"])
    if rule.get("remediation_script_id"):
        rule["remediation_script_id"] = str(rule["remediation_script_id"])
    return rule

@router.post("/rules")
async def create_rule(rule: DetectionRule):
    db = get_database()
    rule_data = rule.model_dump()
    result = await db["rules"].insert_one(rule_data)
    return {"status": "success", "id": str(result.inserted_id)}

@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, updates: dict):
    db = get_database()
    try:
        oid = ObjectId(rule_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    existing = await db["rules"].find_one({"_id": oid})
    if not existing:
        raise HTTPException(status_code=404, detail="Rule not found")

    allowed = {"name", "pattern", "severity", "action_level", "description",
               "enabled", "os_type", "tags", "remediation_script_id"}
    update_data = {k: v for k, v in updates.items() if k in allowed}

    await db["rules"].update_one({"_id": oid}, {"$set": update_data})

    # Invalidate the rule cache so changes take effect immediately
    from app.modules.analysis.service import _rule_cache
    _rule_cache["loaded_at"] = 0

    return {"status": "success", "message": "Rule updated"}

@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    db = get_database()
    try:
        oid = ObjectId(rule_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    result = await db["rules"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Rule not found")

    from app.modules.analysis.service import _rule_cache
    _rule_cache["loaded_at"] = 0

    return {"status": "success", "message": "Rule deleted"}


# ── AI Analysis ──

@router.post("/{incident_id}/analyze")
async def analyze_incident_with_ai(incident_id: str):
    """
    Triggers the AI to look at a specific incident and related logs.
    """
    db = get_database()

    # 1. Fetch Incident
    try:
        inc_oid = ObjectId(incident_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid ID")

    incident = await db["incidents"].find_one({"_id": inc_oid})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # 2. Fetch Related Logs (The Context)
    logs_cursor = db["logs"].find(
        {"server_id": incident["server_id"]}
    ).sort("timestamp", -1).limit(20)

    logs = await logs_cursor.to_list(length=20)

    # Extract just the message text for the AI
    log_messages = [log.get("message", "") for log in logs]
    # Reverse so they are in chronological order (Oldest -> Newest) for the AI
    log_messages.reverse()

    # 3. Ask Llama 3
    analysis_result = await ai_service.analyze_incident(
        incident_description=incident["description"],
        logs=log_messages
    )

    # 4. Save the Result to DB (So we don't have to ask AI twice)
    await db["incidents"].update_one(
        {"_id": inc_oid},
        {"$set": {"ai_analysis": analysis_result}}
    )

    return {
        "status": "success",
        "incident_id": incident_id,
        "ai_analysis": analysis_result
    }
