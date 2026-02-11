from fastapi import APIRouter, HTTPException
from app.modules.analysis.ai_service import AIService
from app.core.database import get_database
from bson import ObjectId

router = APIRouter()
ai_service = AIService()

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
    # We grab the logs from the SAME server that triggered the incident.
    # In a real app, we would filter by time range (incident_time +/- 5 mins).
    # For now, we just get the last 20 logs from that server.
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