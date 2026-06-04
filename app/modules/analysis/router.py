from app.core.constants import Collections, WSTopic, UserRole
import re as re_mod

from fastapi import APIRouter, HTTPException, Query, Depends
from app.core.errors import http_error
from typing import Optional
from app.modules.analysis.schemas import DetectionRule
from app.core.auth import CurrentUser, ensure_server_access, get_current_user, require_role
from app.core.database import get_database
from app.core.events import event_bus
from bson import ObjectId

router = APIRouter()
_operator = require_role(UserRole.OPERATOR.value)
_admin = require_role(UserRole.ADMIN.value)


def _bust_rule_cache() -> None:
    from app.modules.analysis.service import _rule_cache
    _rule_cache["loaded_at"] = 0


# ── Rules CRUD ──

@router.get("/rules")
async def list_rules(
    severity: Optional[str] = Query(None, description="Filter: critical, high, medium, low"),
    os_type: Optional[str] = Query(None, description="Filter: linux, windows, common"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled/disabled"),
    search: Optional[str] = Query(None, description="Search name or pattern"),
    owner_type: Optional[str] = Query(None, description="Phase 28.5: filter by global|server"),
    owner_id: Optional[str] = Query(None, description="Phase 28.5: filter server-scoped rules to a specific server"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    db = get_database()
    query = {}
    if severity:
        query["severity"] = severity
    if os_type:
        query["os_type"] = os_type
    if enabled is not None:
        query["enabled"] = enabled
    if owner_type in ("global", "server"):
        query["owner_type"] = owner_type
    if owner_id:
        query["owner_id"] = owner_id
    if search:
        pattern = re_mod.compile(re_mod.escape(search), re_mod.IGNORECASE)
        query["$or"] = [{"name": pattern}, {"pattern": pattern}]

    total = await db[Collections.RULES].count_documents(query)
    skip = (page - 1) * page_size
    rules = await db[Collections.RULES].find(query).sort("created_at", -1).skip(skip).limit(page_size).to_list(length=page_size)
    for r in rules:
        r["_id"] = str(r["_id"])
        if "remediation_script_id" in r and r["remediation_script_id"]:
            r["remediation_script_id"] = str(r["remediation_script_id"])
    return {"total": total, "page": page, "page_size": page_size, "results": rules}

@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    db = get_database()
    try:
        rule = await db[Collections.RULES].find_one({"_id": ObjectId(rule_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule["_id"] = str(rule["_id"])
    if rule.get("remediation_script_id"):
        rule["remediation_script_id"] = str(rule["remediation_script_id"])
    return rule

@router.post("/rules")
async def create_rule(rule: DetectionRule, user: CurrentUser = Depends(_admin)):
    from datetime import datetime, timezone
    db = get_database()
    rule_data = rule.model_dump()

    # Phase 28.5 — ownership validation
    owner_type = rule_data.get("owner_type", "global")
    owner_id = rule_data.get("owner_id")
    if owner_type == "server":
        if not owner_id:
            raise HTTPException(status_code=422, detail="owner_id is required when owner_type=='server'")
        try:
            srv = await db[Collections.SERVERS].find_one({"_id": ObjectId(owner_id)}, {"_id": 1})
        except Exception:
            raise HTTPException(status_code=422, detail="owner_id is not a valid server id")
        if not srv:
            raise HTTPException(status_code=422, detail=f"Server {owner_id} not found")
    else:
        if owner_id is not None:
            raise HTTPException(status_code=422, detail="owner_id must be null when owner_type=='global'")

    now = datetime.now(timezone.utc)
    rule_data["created_at"] = now
    rule_data["updated_at"] = None
    result = await db[Collections.RULES].insert_one(rule_data)
    _bust_rule_cache()
    event_bus.emit(WSTopic.RULES, "rule.created", {"rule_id": str(result.inserted_id)})
    if owner_type == "server" and owner_id:
        event_bus.emit(f"servers.{owner_id}.rules", "rule.created", {"rule_id": str(result.inserted_id)})
    return {"status": "success", "id": str(result.inserted_id)}


@router.post("/servers/{server_id}/rules")
async def create_rule_for_server(server_id: str, rule: DetectionRule, user: CurrentUser = Depends(_admin)):
    """
    Phase 28.5 convenience endpoint — creates a rule pre-scoped to a server.
    The path parameter is authoritative: any owner_type / owner_id in the
    body is overridden so a buggy client can't insert a rule scoped to the
    wrong server.
    """
    rule.owner_type = "server"
    rule.owner_id = server_id
    return await create_rule(rule)


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, updates: dict, user: CurrentUser = Depends(_admin)):
    db = get_database()
    try:
        oid = ObjectId(rule_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    existing = await db[Collections.RULES].find_one({"_id": oid})
    if not existing:
        raise HTTPException(status_code=404, detail="Rule not found")

    from datetime import datetime, timezone
    # Phase 28.5 — `remediation_script_id_windows` added (was silently dropped
    # by the pre-28.5 allowed-fields list, breaking Windows OS-override edits).
    # `owner_type` / `owner_id` are intentionally NOT included — ownership is
    # immutable after creation to avoid orphaning per-server rule rows.
    allowed = {"name", "pattern", "severity", "action_level", "description",
               "enabled", "os_type", "tags",
               "remediation_script_id", "remediation_script_id_windows"}
    update_data = {k: v for k, v in updates.items() if k in allowed}
    update_data["updated_at"] = datetime.now(timezone.utc)

    await db[Collections.RULES].update_one({"_id": oid}, {"$set": update_data})
    _bust_rule_cache()
    event_bus.emit(WSTopic.RULES, "rule.updated", {"rule_id": str(oid)})
    if existing.get("owner_type") == "server" and existing.get("owner_id"):
        event_bus.emit(
            f"servers.{existing['owner_id']}.rules",
            "rule.updated",
            {"rule_id": str(oid)},
        )

    return {"status": "success", "message": "Rule updated"}

@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, user: CurrentUser = Depends(_admin)):
    db = get_database()
    try:
        oid = ObjectId(rule_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    existing = await db[Collections.RULES].find_one({"_id": oid}, {"owner_type": 1, "owner_id": 1})
    result = await db[Collections.RULES].delete_one({"_id": oid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Rule not found")

    _bust_rule_cache()
    event_bus.emit(WSTopic.RULES, "rule.deleted", {"rule_id": str(oid)})
    if existing and existing.get("owner_type") == "server" and existing.get("owner_id"):
        event_bus.emit(
            f"servers.{existing['owner_id']}.rules",
            "rule.deleted",
            {"rule_id": str(oid)},
        )

    return {"status": "success", "message": "Rule deleted"}


# ── AI Analysis ──

@router.post("/server-overview/{server_id}")
async def analyze_server_overview(server_id: str, hours: int = Query(24, ge=1, le=72), user: CurrentUser = Depends(_operator)):
    """
    Run the server-overview AI agent: a whole-server diagnostic + risk analysis
    over the last `hours` hours (1–72). Manual diagnostic commands only — no
    executable command lifecycle, no status-change suggestions.

    Registered BEFORE the dynamic /{incident_id}/analyze route below so the
    static `server-overview` segment matches first.
    """
    from app.modules.ai.server_graph import run_server_overview

    ensure_server_access(user, server_id)
    db = get_database()
    try:
        srv_oid = ObjectId(server_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid server_id")

    if not await db[Collections.SERVERS].find_one({"_id": srv_oid}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Server not found")

    # Mark in-progress so the frontend can show a spinner while the agent runs.
    await db[Collections.SERVERS].update_one(
        {"_id": srv_oid},
        {"$set": {"ai_analysis_in_progress": True}},
    )

    try:
        result = await run_server_overview(server_id, hours=hours)
    except Exception as exc:
        await db[Collections.SERVERS].update_one(
            {"_id": srv_oid},
            {"$set": {"ai_analysis_in_progress": False}},
        )
        raise http_error(503, "AI server overview failed — please try again.", exc, "server overview")

    await db[Collections.SERVERS].update_one(
        {"_id": srv_oid},
        {"$set": {"ai_analysis_in_progress": False}},
    )

    return {
        "status": "success",
        "server_id": server_id,
        "analysis_id": result["analysis_id"],
        "run_id": result["run_id"],
        "summary": result["summary"],
        "markdown": result["markdown"],
        "manual_commands": result["manual_commands"],
        "confidence": result["confidence"],
        "hours": result["hours"],
        "analyzed_at": result["analyzed_at"],
    }


@router.post("/{incident_id}/analyze")
async def analyze_incident_with_ai(incident_id: str, user: CurrentUser = Depends(_operator)):
    """
    Run the LangGraph triage agent on an incident. Fetches its own evidence
    via tools, produces a structured analysis, and saves ai_analysis to DB.
    """
    from app.modules.ai.triage_graph import run_triage

    db = get_database()
    try:
        inc_oid = ObjectId(incident_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

    inc = await db[Collections.INCIDENTS].find_one({"_id": inc_oid}, {"server_id": 1})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_server_access(user, str(inc.get("server_id")))

    # Mark analysis as in-progress so any page showing this incident
    # can immediately reflect the loading state (persisted across navigation).
    await db[Collections.INCIDENTS].update_one(
        {"_id": inc_oid},
        {"$set": {"ai_analysis_in_progress": True}},
    )

    try:
        result = await run_triage(incident_id)
    except Exception as exc:
        await db[Collections.INCIDENTS].update_one(
            {"_id": inc_oid},
            {"$set": {"ai_analysis_in_progress": False}},
        )
        raise http_error(503, "AI triage failed — please try again.", exc, "incident triage")

    await db[Collections.INCIDENTS].update_one(
        {"_id": inc_oid},
        {"$set": {
            "ai_analysis": result["markdown"],
            "ai_analyzed_at": result["analyzed_at"],
            "ai_analysis_in_progress": False,
            "ai_manual_commands": result["manual_commands"],
        }},
    )

    return {
        "status": "success",
        "incident_id": incident_id,
        "analysis_id": result["analysis_id"],
        "run_id": result["run_id"],
        "ai_analysis": result["markdown"],
        "suggested_command_ids": result["suggested_command_ids"],
        "manual_commands": result["manual_commands"],
        "pending_action_ids": result["pending_action_ids"],
        "confidence": result["confidence"],
        "analyzed_at": result["analyzed_at"],
    }
