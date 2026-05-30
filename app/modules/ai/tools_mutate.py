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


# ── Phase 28.4 — Per-server script / rule disable + manual remediation push ──
#
# These executors back the three new action types emitted by the script-review
# agent on `suggest`-mode servers. The disable shims write a per-server
# exclusion list onto the script or rule doc. Phase 28.5's per-server library
# will eventually supersede the list approach, but this is the cheap forward-
# compatible version (zero new collections, zero migrations).

async def _execute_disable_script_for_server(server_id: str, script_id: str, reason: str) -> dict:
    """Append server_id to `scripts.disabled_for_servers[]` (idempotent)."""
    from bson import ObjectId
    db = get_database()
    if not server_id or not script_id:
        return {"executed": False, "error": "server_id and script_id required"}
    try:
        oid = ObjectId(script_id)
    except Exception:
        return {"executed": False, "error": "Invalid script_id"}
    result = await db["scripts"].update_one(
        {"_id": oid},
        {
            "$addToSet": {"disabled_for_servers": server_id},
            "$set": {
                f"disabled_for_server_reasons.{server_id}": reason or "(no reason)",
                "updated_at": utc_now(),
            },
        },
    )
    return {
        "executed": result.matched_count > 0,
        "script_id": script_id,
        "server_id": server_id,
        "action": "disable_script_for_server",
    }


async def _execute_disable_rule_for_server(server_id: str, rule_id: str, reason: str) -> dict:
    """Append server_id to `rules.disabled_for_servers[]` (idempotent)."""
    from bson import ObjectId
    db = get_database()
    if not server_id or not rule_id:
        return {"executed": False, "error": "server_id and rule_id required"}
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return {"executed": False, "error": "Invalid rule_id"}
    result = await db["rules"].update_one(
        {"_id": oid},
        {
            "$addToSet": {"disabled_for_servers": server_id},
            "$set": {
                f"disabled_for_server_reasons.{server_id}": reason or "(no reason)",
                "updated_at": utc_now(),
            },
        },
    )
    # Bust the analysis rule cache so the change is effective on the next tick.
    # (Phase 28.5 fix — the previous `AnalysisService._cached_rules = None`
    # targeted a non-existent attribute, so the disable was silently masked
    # by the 5-min cache TTL.)
    try:
        from app.modules.analysis.service import _rule_cache
        _rule_cache["loaded_at"] = 0
    except Exception:
        pass
    return {
        "executed": result.matched_count > 0,
        "rule_id": rule_id,
        "server_id": server_id,
        "action": "disable_rule_for_server",
    }


async def _execute_suggest_manual_remediation(
    incident_id: str,
    manual_commands: list,
    reason: str,
    automation_log_id: str = "",
) -> dict:
    """Attach the AI-proposed manual checklist to the incident doc.

    Phase 28.5.2 — writes to `ai_remediation_manual_commands` (NOT
    `ai_manual_commands`) so the operator's original incident-triage checklist
    isn't clobbered. The two sources live side-by-side on the incident detail
    page so the operator can see what the triage agent originally suggested AND
    what the post-remediation review proposed when the script didn't fix it.

    The meta sub-doc links back to the remediation run that produced these
    commands so the incident page can render "View remediation run →" linking
    to /automation/history/{automation_log_id}.
    """
    from bson import ObjectId
    db = get_database()
    if not incident_id or not manual_commands:
        return {"executed": False, "error": "incident_id and manual_commands required"}
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return {"executed": False, "error": "Invalid incident_id"}
    meta = {
        "reason": reason or "",
        "automation_log_id": automation_log_id or None,
        "incident_id": incident_id,
        "created_at": utc_now(),
    }
    result = await db["incidents"].update_one(
        {"_id": oid},
        {"$set": {
            "ai_remediation_manual_commands": manual_commands,
            "ai_remediation_manual_commands_meta": meta,
            "updated_at": utc_now(),
        }},
    )

    # Also write a denormalised copy onto the automation_logs row so the
    # /automation/history/{id} detail page can render the checklist inline
    # without an extra incident fetch. The incident page remains the canonical
    # source of truth — this is purely a UX-side cache.
    if automation_log_id:
        try:
            await db["automation_logs"].update_one(
                {"_id": ObjectId(automation_log_id)},
                {"$set": {
                    "ai_remediation_manual_commands": manual_commands,
                    "ai_remediation_manual_commands_meta": meta,
                }},
            )
        except Exception:
            # Best-effort — the incident write above is the canonical one.
            pass

    return {
        "executed": result.matched_count > 0,
        "incident_id": incident_id,
        "command_count": len(manual_commands),
        "automation_log_id": automation_log_id,
        "action": "suggest_manual_remediation",
    }


# ── Phase 28.5 — Per-server library actions (create rule, create script, swap remediation) ──
#
# These executors back the three new action types the LLM can propose from the
# script-review / server-overview / anomaly-triage flows. Each one inserts a
# server-scoped rule or script and auto-flips the server's matching library
# mode from `global` to `both` so the new entry actually fires.
#
# Forward-compat: shares the same `disabled_for_servers` shim semantics as
# 28.4. When the user manages library mode via the server edit page, both the
# explicit mode and the 28.4 shim continue to coexist.

from app.core.events import event_bus


async def _auto_flip_to_both(server_id: str, mode_field: str) -> bool:
    """If the server's library mode for `mode_field` is currently `global`,
    flip it to `both` so the new server-scoped entry actually applies. Returns
    True iff the flip happened (caller may surface this in the response)."""
    from bson import ObjectId
    db = get_database()
    try:
        srv_oid = ObjectId(server_id)
    except Exception:
        return False
    result = await db["servers"].update_one(
        {"_id": srv_oid, mode_field: "global"},
        {"$set": {mode_field: "both", "updated_at": utc_now()}},
    )
    if result.modified_count > 0:
        event_bus.emit(f"servers.{server_id}.status", "server.updated", {"server_id": server_id})
        return True
    return False


async def _execute_create_server_rule(
    server_id: str,
    name: str,
    pattern: str,
    severity: str,
    action_level: int,
    description: str,
    os_type: str = "linux",
    tags: Optional[list] = None,
    remediation_script_id: Optional[str] = None,
    reason: str = "",
    ai_analysis_id: Optional[str] = None,
) -> dict:
    """Insert a server-scoped rule from an approved AI suggestion. Auto-flips
    `rule_library_mode` to `both` when needed."""
    from bson import ObjectId
    db = get_database()
    if not server_id or not name or not pattern:
        return {"executed": False, "error": "server_id, name and pattern required"}
    try:
        srv_oid = ObjectId(server_id)
    except Exception:
        return {"executed": False, "error": "Invalid server_id"}
    if not await db["servers"].find_one({"_id": srv_oid}, {"_id": 1}):
        return {"executed": False, "error": f"Server {server_id} not found"}

    now = utc_now()
    rule_doc = {
        "name": name,
        "pattern": pattern,
        "severity": severity,
        "action_level": int(action_level) if action_level is not None else 3,
        "description": description or "",
        "enabled": True,
        "os_type": os_type or "common",
        "tags": tags or [],
        "remediation_script_id": remediation_script_id,
        "remediation_script_id_windows": None,
        "owner_type": "server",
        "owner_id": server_id,
        "ai_origin": {"reason": reason, "ai_analysis_id": ai_analysis_id} if ai_analysis_id else None,
        "created_at": now,
        "updated_at": None,
    }
    result = await db["rules"].insert_one(rule_doc)
    rule_id = str(result.inserted_id)

    # Bust the global rule cache so the new rule is picked up on the next tick.
    try:
        from app.modules.analysis.service import _rule_cache
        _rule_cache["loaded_at"] = 0
    except Exception:
        pass

    auto_flipped = await _auto_flip_to_both(server_id, "rule_library_mode")

    event_bus.emit("rules", "rule.created", {"rule_id": rule_id})
    event_bus.emit(f"servers.{server_id}.rules", "rule.created", {"rule_id": rule_id})

    return {
        "executed": True,
        "rule_id": rule_id,
        "server_id": server_id,
        "auto_flipped_to_both": auto_flipped,
        "action": "create_server_rule",
    }


async def _execute_create_server_script(
    server_id: str,
    name: str,
    description: str,
    language: str,
    content: str,
    target_os: str = "linux",
    category: str = "recovery",
    reason: str = "",
    ai_analysis_id: Optional[str] = None,
) -> dict:
    """Insert a server-scoped script from an approved AI suggestion. Auto-flips
    `script_library_mode` to `both` when needed."""
    from bson import ObjectId
    db = get_database()
    if not server_id or not name or not content:
        return {"executed": False, "error": "server_id, name and content required"}
    try:
        srv_oid = ObjectId(server_id)
    except Exception:
        return {"executed": False, "error": "Invalid server_id"}
    if not await db["servers"].find_one({"_id": srv_oid}, {"_id": 1}):
        return {"executed": False, "error": f"Server {server_id} not found"}

    now = utc_now()
    script_doc = {
        "name": name,
        "description": description or "",
        "language": language or "bash",
        "content": content,
        "target_os": target_os or "linux",
        "category": category or "recovery",
        "enabled": True,
        "owner_type": "server",
        "owner_id": server_id,
        "ai_origin": {"reason": reason, "ai_analysis_id": ai_analysis_id} if ai_analysis_id else None,
        "created_at": now,
        "updated_at": now,
    }
    result = await db["scripts"].insert_one(script_doc)
    script_id = str(result.inserted_id)

    auto_flipped = await _auto_flip_to_both(server_id, "script_library_mode")

    event_bus.emit("scripts", "script.created", {"script_id": script_id})
    event_bus.emit(f"servers.{server_id}.scripts", "script.created", {"script_id": script_id})

    return {
        "executed": True,
        "script_id": script_id,
        "server_id": server_id,
        "auto_flipped_to_both": auto_flipped,
        "action": "create_server_script",
    }


async def _execute_swap_remediation_script(
    server_id: str,
    rule_id: str,
    new_script_content: str,
    language: str,
    target_os: str = "linux",
    reason: str = "",
    ai_analysis_id: Optional[str] = None,
) -> dict:
    """
    Insert a server-scoped script with the same *name* as the rule's current
    remediation so the name-match resolver in `_resolve_script_id` prefers it
    on this server only. The global script is left untouched.

    If the rule has no remediation script, returns an error — there's nothing
    to "swap". For Windows we prefer `remediation_script_id_windows` when set.
    """
    from bson import ObjectId
    db = get_database()
    if not server_id or not rule_id or not new_script_content:
        return {"executed": False, "error": "server_id, rule_id and new_script_content required"}
    try:
        srv_oid = ObjectId(server_id)
        r_oid = ObjectId(rule_id)
    except Exception:
        return {"executed": False, "error": "Invalid id"}
    server = await db["servers"].find_one({"_id": srv_oid})
    if not server:
        return {"executed": False, "error": f"Server {server_id} not found"}
    rule = await db["rules"].find_one({"_id": r_oid})
    if not rule:
        return {"executed": False, "error": f"Rule {rule_id} not found"}

    server_os = server.get("os_type", "linux")
    if server_os == "windows" and rule.get("remediation_script_id_windows"):
        current_script_id = rule["remediation_script_id_windows"]
    else:
        current_script_id = rule.get("remediation_script_id")
    if not current_script_id:
        return {"executed": False, "error": "Rule has no remediation script to swap"}

    try:
        current = await db["scripts"].find_one({"_id": ObjectId(current_script_id)})
    except Exception:
        current = None
    if not current:
        return {"executed": False, "error": "Current script not found"}

    # Re-use the create-server-script path so the auto-flip + emit logic is shared.
    return await _execute_create_server_script(
        server_id=server_id,
        name=current["name"],
        description=f"Server-specific replacement (swapped for rule '{rule['name']}')",
        language=language or current.get("language", "bash"),
        content=new_script_content,
        target_os=target_os or current.get("target_os", "linux"),
        category=current.get("category", "recovery"),
        reason=reason,
        ai_analysis_id=ai_analysis_id,
    )


async def _execute_create_server_rule_with_script(
    server_id: str,
    # Rule fields
    rule_name: str,
    pattern: str,
    severity: str,
    action_level: int,
    rule_description: str,
    os_type: str = "linux",
    tags: Optional[list] = None,
    # Script fields
    script_name: str = "",
    script_description: str = "",
    language: str = "bash",
    content: str = "",
    target_os: str = "linux",
    category: str = "recovery",
    # Shared metadata
    reason: str = "",
    ai_analysis_id: Optional[str] = None,
) -> dict:
    """
    Atomically insert a server-scoped script AND a server-scoped rule that
    points to it via `remediation_script_id`. This is the fix for the
    orphan-script hole: a brand-new helper is useless unless a rule fires it,
    so the LLM must propose both together.

    Inlines the two insert bodies (rather than calling the existing executors)
    so we get one timestamp, one auto-flip per mode, and a single emit per
    inserted row. Script is inserted first so its `_id` is available for the
    rule's `remediation_script_id`. If the rule insert fails, the script is
    deleted (best-effort rollback — PFE Mongo isn't a replica set, so no real
    transactions).
    """
    from bson import ObjectId
    db = get_database()
    if not server_id or not rule_name or not pattern or not script_name or not content:
        return {
            "executed": False,
            "error": "server_id, rule_name, pattern, script_name and content required",
        }
    try:
        srv_oid = ObjectId(server_id)
    except Exception:
        return {"executed": False, "error": "Invalid server_id"}
    if not await db["servers"].find_one({"_id": srv_oid}, {"_id": 1}):
        return {"executed": False, "error": f"Server {server_id} not found"}

    now = utc_now()
    ai_origin = {"reason": reason, "ai_analysis_id": ai_analysis_id} if ai_analysis_id else None

    # 1. Insert the server-scoped script first.
    script_doc = {
        "name": script_name,
        "description": script_description or "",
        "language": language or "bash",
        "content": content,
        "target_os": target_os or "linux",
        "category": category or "recovery",
        "enabled": True,
        "owner_type": "server",
        "owner_id": server_id,
        "ai_origin": ai_origin,
        "created_at": now,
        "updated_at": now,
    }
    script_result = await db["scripts"].insert_one(script_doc)
    script_id = str(script_result.inserted_id)

    # 2. Insert the rule pointing at the just-created script. On failure, roll
    #    back the script so we don't leave an orphan behind.
    rule_doc = {
        "name": rule_name,
        "pattern": pattern,
        "severity": severity,
        "action_level": int(action_level) if action_level is not None else 3,
        "description": rule_description or "",
        "enabled": True,
        "os_type": os_type or "common",
        "tags": tags or [],
        "remediation_script_id": script_id,
        "remediation_script_id_windows": None,
        "owner_type": "server",
        "owner_id": server_id,
        "ai_origin": ai_origin,
        "created_at": now,
        "updated_at": None,
    }
    try:
        rule_result = await db["rules"].insert_one(rule_doc)
        rule_id = str(rule_result.inserted_id)
    except Exception as exc:
        try:
            await db["scripts"].delete_one({"_id": script_result.inserted_id})
        except Exception:
            pass
        return {"executed": False, "error": f"Rule insert failed, script rolled back: {exc}"}

    # 3. Bust the global rule cache so the new rule is picked up next tick.
    try:
        from app.modules.analysis.service import _rule_cache
        _rule_cache["loaded_at"] = 0
    except Exception:
        pass

    # 4. Auto-flip BOTH modes — script first, then rule.
    auto_flipped_script = await _auto_flip_to_both(server_id, "script_library_mode")
    auto_flipped_rule = await _auto_flip_to_both(server_id, "rule_library_mode")

    # 5. Emit for both surfaces.
    event_bus.emit("scripts", "script.created", {"script_id": script_id})
    event_bus.emit(f"servers.{server_id}.scripts", "script.created", {"script_id": script_id})
    event_bus.emit("rules", "rule.created", {"rule_id": rule_id})
    event_bus.emit(f"servers.{server_id}.rules", "rule.created", {"rule_id": rule_id})

    return {
        "executed": True,
        "rule_id": rule_id,
        "script_id": script_id,
        "server_id": server_id,
        "auto_flipped_rule_mode": auto_flipped_rule,
        "auto_flipped_script_mode": auto_flipped_script,
        "action": "create_server_rule_with_script",
    }


# ── Bookkeeping helpers ──────────────────────────────────────────────────────

async def clear_pending_actions_for_source(source_type: str, source_id: str) -> int:
    """
    Delete every PENDING ai_actions row for a given source. Called at the
    start of each re-analysis so the new run's recommendations aren't sitting
    next to stale pending ones from the previous run.

    Already-approved or already-rejected rows are LEFT IN PLACE — they're
    historical audit trail, not active recommendations.

    Returns the count of rows deleted.
    """
    if not source_id:
        return 0
    db = get_database()
    result = await db["ai_actions"].delete_many({
        "source_type": source_type,
        "source_id": source_id,
        "status": "pending",
    })
    return result.deleted_count


# ── Pending-action queue helper (suggest level) ──────────────────────────────

async def _queue_action(
    *,
    action_type: str,
    payload: dict,
    run_id: str,
    source_type: str,
    source_id: str,
    server_id: str,
) -> str:
    db = get_database()
    doc = {
        "action_type": action_type,
        "payload": payload,
        "run_id": run_id,
        "source_type": source_type,
        "source_id": source_id,
        "server_id": server_id,
        "status": "pending",
        "created_at": utc_now(),
        "decided_at": None,
        "decided_by": None,
    }
    result = await db["ai_actions"].insert_one(doc)
    return str(result.inserted_id)


# ── Tool factories — called by policy.py to produce level-appropriate tools ──
#
# Each factory takes the autonomy level, run_id, AND the source/server context
# of the current triage run so the queued ai_actions row carries the link back
# to its originating incident or anomaly. This lets the frontend show "actions
# proposed for THIS incident" without scanning every payload.

def make_dismiss_anomaly_tool(
    level: str, run_id: str, source_type: str, source_id: str, server_id: str,
) -> Optional[object]:
    if level == "suggest":
        @tool
        async def dismiss_anomaly(observation_id: str, reason: str) -> str:
            """
            Queue a request to dismiss a Tier 2 anomaly observation (mark as
            not interesting / false positive). NOTHING happens until an
            operator approves the queued action in the AI Actions page.

            Use when, after investigating, you conclude the anomaly is benign
            (known noisy pattern, expected cron, health-check chatter, etc).
            Provide the observation_id and a brief one-line reason.
            """
            action_id = await _queue_action(
                action_type="dismiss_anomaly",
                payload={"observation_id": observation_id, "reason": reason},
                run_id=run_id,
                source_type=source_type,
                source_id=source_id,
                server_id=server_id,
            )
            return json.dumps({"queued": True, "pending_action_id": action_id, "message": "Dismiss queued for operator approval"})
        return dismiss_anomaly
    return None


def make_promote_anomaly_tool(
    level: str, run_id: str, source_type: str, source_id: str, server_id: str,
) -> Optional[object]:
    if level == "suggest":
        @tool
        async def promote_anomaly(observation_id: str) -> str:
            """
            Queue a request to promote a Tier 2 anomaly observation to a real
            incident. NOTHING happens until an operator approves the queued
            action in the AI Actions page.

            Use when the anomaly shows strong signs of a genuine security
            threat that warrants the full incident workflow (alerts, automation).
            """
            action_id = await _queue_action(
                action_type="promote_anomaly",
                payload={"observation_id": observation_id},
                run_id=run_id,
                source_type=source_type,
                source_id=source_id,
                server_id=server_id,
            )
            return json.dumps({"queued": True, "pending_action_id": action_id, "message": "Promotion queued for operator approval"})
        return promote_anomaly
    return None


def make_mark_false_positive_tool(
    level: str, run_id: str, source_type: str, source_id: str, server_id: str,
) -> Optional[object]:
    if level == "suggest":
        @tool
        async def mark_incident_false_positive(incident_id: str, reason: str) -> str:
            """
            Queue a request to mark an incident as a false positive. NOTHING
            happens until an operator approves the queued action in the AI
            Actions page.

            Use when the evidence clearly shows the alert is benign — for
            example, a rule misfire on legitimate maintenance traffic.
            Provide a short one-line reason explaining why.
            """
            action_id = await _queue_action(
                action_type="mark_incident_false_positive",
                payload={"incident_id": incident_id, "reason": reason},
                run_id=run_id,
                source_type=source_type,
                source_id=source_id,
                server_id=server_id,
            )
            return json.dumps({"queued": True, "pending_action_id": action_id, "message": "False-positive flag queued for operator approval"})
        return mark_incident_false_positive
    return None
