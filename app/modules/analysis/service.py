from app.core.constants import (
    Collections, WSTopic, DetectionDefaults, AutomationSkippedReason, AutomationFailureReason,
    NotificationType, NotificationCategory, NotificationSeverity,
)
import re
import time
from datetime import datetime, timezone, timedelta
from typing import Optional
from app.core.database import get_database
from app.modules.analysis.schemas import IncidentInDB, ActionLevel, IncidentStatus
from app.modules.logs.schemas import LogEntryInDB
from bson import ObjectId
from app.modules.automation.service import AutomationService
from app.modules.notifications.service import NotificationService
from app.modules.notifications.schemas import AlertPayload
from app.modules.heuristics.service import HeuristicService
from app.modules.anomalies.service import AnomaliesService
from app.modules.notifications.feed import notify
from app.core.events import event_bus
from app.core.datetime_utils import to_utc


# Map incident severity → in-app notification severity (loudness of the bell row).
_INCIDENT_NOTIF_SEVERITY = {
    "critical": NotificationSeverity.ERROR,
    "high": NotificationSeverity.WARNING,
}


async def _notify_incident_created(incident_id: str, server_id: str, severity, rule_name: str):
    """In-app notification for a freshly-created incident (core event)."""
    sev = severity or ""
    await notify(
        type=NotificationType.INCIDENT_CREATED,
        category=NotificationCategory.INCIDENT,
        severity=_INCIDENT_NOTIF_SEVERITY.get(sev, NotificationSeverity.INFO),
        title=f"New {sev} incident".strip() if sev else "New incident",
        body=(rule_name or "")[:160],
        link=f"/incidents/{incident_id}",
        server_id=server_id,
        entity_type="incident",
        entity_id=incident_id,
    )


# ========================================================================
# Remediation / Detection Tunables — GLOBAL DEFAULTS
# All of these can be overridden per-server via DetectionConfig.
# ========================================================================
VERIFICATION_WINDOW_MINUTES = DetectionDefaults.VERIFICATION_WINDOW_MINUTES    # watch window after script runs
MAX_REMEDIATION_ATTEMPTS = DetectionDefaults.MAX_REMEDIATION_ATTEMPTS          # retries before escalation
RECENT_INCIDENT_LOOKBACK_MINUTES = DetectionDefaults.INCIDENT_LOOKBACK_MINUTES # dedup lookback for OPEN/VERIFYING
RECURRENCE_STREAK_THRESHOLD = DetectionDefaults.RECURRENCE_STREAK_THRESHOLD    # consecutive "fix → recur" before pausing automation
RECURRENCE_LOOKBACK_HOURS = DetectionDefaults.RECURRENCE_LOOKBACK_HOURS        # how recent last resolution must be to count as chain


def _cfg(server: dict) -> dict:
    """Return the server's detection_config dict, falling back to empty."""
    return server.get("detection_config") or {}

# ========================================================================
# OPT-4: RULE CACHE
# Rules rarely change (maybe once a week). Instead of re-querying MongoDB
# and re-compiling regex every 60 seconds for every server, we cache them
# in memory with a 5-minute TTL. 
# ========================================================================
_rule_cache = {
    "rules": [],         # List of {"data": rule_dict, "compiled_pattern": re.Pattern}
    "loaded_at": 0,      # Unix timestamp of when cache was last refreshed
    "ttl": 300,          # 5 minutes
}


async def _get_cached_rules():
    """
    Returns compiled rules from cache. Re-fetches from MongoDB only if
    the cache is older than TTL (5 minutes).
    """
    now = time.time()
    if now - _rule_cache["loaded_at"] > _rule_cache["ttl"]:
        db = get_database()
        rules_data = await db[Collections.RULES].find({"enabled": True}).to_list(length=200)
        
        compiled = []
        for r in rules_data:
            try:
                compiled.append({
                    "data": r,
                    "compiled_pattern": re.compile(r["pattern"], re.IGNORECASE)
                })
            except re.error:
                print(f"❌ Invalid Regex in Rule {r['name']}")
        
        _rule_cache["rules"] = compiled
        _rule_cache["loaded_at"] = now
        print(f"🔄 Rule cache refreshed: {len(compiled)} rules compiled")
    
    return _rule_cache["rules"]


# ========================================================================
# Phase 28.5 — Per-server library scoping
# Each server independently picks which slice of the global+private library
# it sees. This is a pure-Python filter on top of the existing global cache;
# no extra DB calls, no cache-per-server. Switching a server's mode is
# non-destructive — private rules/scripts stay in the DB and just become
# inactive until the mode includes them again.
# ========================================================================
def _rules_for_server(all_rules: list[dict], server_doc: dict) -> list[dict]:
    """Filter the cached rule list by the server's `rule_library_mode`."""
    mode = server_doc.get("rule_library_mode", "global")
    sid = str(server_doc["_id"])

    if mode == "global":
        return [r for r in all_rules if r["data"].get("owner_type", "global") == "global"]
    if mode == "server":
        return [
            r for r in all_rules
            if r["data"].get("owner_type") == "server" and r["data"].get("owner_id") == sid
        ]
    # mode == "both"
    return [
        r for r in all_rules
        if r["data"].get("owner_type", "global") == "global"
        or (r["data"].get("owner_type") == "server" and r["data"].get("owner_id") == sid)
    ]


async def _resolve_script_id(rule: dict, server: dict, server_os: str, db) -> Optional[str]:
    """
    Phase 28.5 — script resolution with name-match auto-override.

      - global mode: return the rule's OS-appropriate script id as-is.
      - server/both mode: look up the candidate's name and prefer a server-owned
        script with the same name. In `server` mode, if no server-owned twin
        exists, return None (no fallback to global). In `both` mode, fall back
        to the global candidate.
    """
    if server_os == "windows" and rule.get("remediation_script_id_windows"):
        candidate_id = rule["remediation_script_id_windows"]
    else:
        candidate_id = rule.get("remediation_script_id")

    if not candidate_id:
        return None

    mode = server.get("script_library_mode", "global")
    if mode == "global":
        return candidate_id

    sid = str(server["_id"])

    try:
        candidate = await db[Collections.SCRIPTS].find_one(
            {"_id": ObjectId(candidate_id)}, {"name": 1}
        )
    except Exception:
        candidate = None
    if not candidate:
        # Broken pointer — let the downstream `script_missing` path surface it.
        return candidate_id

    server_match = await db[Collections.SCRIPTS].find_one(
        {
            "owner_type": "server",
            "owner_id": sid,
            "name": candidate["name"],
            "enabled": True,
        },
        {"_id": 1},
    )

    if server_match:
        return str(server_match["_id"])
    if mode == "server":
        return None
    return candidate_id


class AnalysisService:

    def __init__(self):
        self.automation_service = AutomationService()
        self.notification_service = NotificationService()
        self.heuristic_service = HeuristicService()
        self.anomalies_service = AnomaliesService()

    async def analyze_logs(self, logs: list[dict]):
        """
        The Core Logic:
        1. Get Rules from cache (OPT-4).
        2. Check every log against every rule.
        3. Create Incidents if matches found (with dedup — OPT-5).
        """
        if not logs:
            return

        db = get_database()

        # 1. Fetch Server OS once
        first_server_id = logs[0]["server_id"]
        server = await db[Collections.SERVERS].find_one({"_id": ObjectId(first_server_id)})
        if not server:
            return

        server_os = server.get("os_type", "linux")

        # 2. OPT-4: Get rules from cache (no DB query if cache is fresh)
        all_rules = await _get_cached_rules()

        # Phase 28.5: filter by the server's library mode (global/server/both)
        # before OS filtering. Pure-Python, no extra DB call.
        all_rules = _rules_for_server(all_rules, server)

        # Filter by OS (pure Python, no DB)
        active_rules = [
            r for r in all_rules
            if r["data"].get("os_type", "common") in ("common", server_os)
        ]

        if not active_rules:
            return

        new_incidents = []
        # Tracks (server_id, rule_id) pairs already queued in this batch so
        # identical L3 rule hits on subsequent log lines don't produce duplicates
        # before the bulk insert runs. L1/L2 are inserted inline and are already
        # covered by the DB dedup query.
        _batch_l3_keys: set[tuple[str, str]] = set()

        # 3. The Matching Loop
        for log in logs:
            log_msg = log.get("message") or ""
            matched_any = False  # tracked for Tier 2 heuristic fallback

            for rule_obj in active_rules:
                rule = rule_obj["data"]
                pattern = rule_obj["compiled_pattern"]

                match = pattern.search(log_msg)

                if match:
                    matched_any = True
                    # Extract named capture groups; always inject server metadata
                    extracted_context = match.groupdict() or {"raw_match": match.group(0)}
                    extracted_context.setdefault("hostname", server.get("hostname", ""))
                    extracted_context.setdefault("os_type", server_os)

                    server_id_str = str(log["server_id"])
                    rule_id_str = str(rule["_id"])
                    now = datetime.now(timezone.utc)

                    # Phase 28.4 — per-server rule disable (operator approved an
                    # AI suggestion to silence this rule on this server). Treated
                    # as no-match so neither incident nor anomaly fallback fires.
                    if server_id_str in (rule.get("disabled_for_servers") or []):
                        matched_any = False  # let heuristics try their luck
                        continue

                    action_level = rule.get("action_level", 3)

                    # Phase 28.5: OS-aware pick + name-match auto-override for
                    # server/both library modes. Falls back to the rule's
                    # OS-appropriate script id in global mode (zero behaviour
                    # change there).
                    candidate_script_id = await _resolve_script_id(rule, server, server_os, db)

                    # ========================================================
                    # State-machine dedup (replaces the old 5-min hard dedup):
                    #
                    #   1. Look for an OPEN or VERIFYING incident on the same
                    #      (server, rule) within the lookback window (30 min).
                    #   2. If found:
                    #        - exhausted    → skip silently (already escalated)
                    #        - verifying & still in the window → the previous
                    #          remediation FAILED. Retry up to MAX_ATTEMPTS,
                    #          then escalate.
                    #        - any other open state → standard dedup; skip
                    #          (this matches the old behaviour but with a
                    #          wider window so we don't churn out duplicates).
                    #   3. If nothing found → fresh detection: create incident
                    #      and (for L1/L2) run script, mark VERIFYING.
                    # ========================================================
                    lookback_cutoff = now - timedelta(
                        minutes=_cfg(server).get("incident_lookback_minutes") or RECENT_INCIDENT_LOOKBACK_MINUTES
                    )
                    existing = await db[Collections.INCIDENTS].find_one(
                        {
                            "server_id": server_id_str,
                            "rule_id": rule_id_str,
                            "status": {"$in": [
                                IncidentStatus.OPEN.value,
                                IncidentStatus.VERIFYING.value,
                            ]},
                            "detected_at": {"$gte": lookback_cutoff},
                        },
                        sort=[("detected_at", -1)],
                    )

                    if existing is not None:
                        existing_id = existing["_id"]

                        # Already escalated: don't retry, don't alert again. Waits for manual resolve.
                        if existing.get("automation_failure_reason") == AutomationFailureReason.REMEDIATION_EXHAUSTED.value:
                            continue

                        verification_until = to_utc(existing.get("verification_until"))
                        in_verification_window = (
                            existing.get("status") == IncidentStatus.VERIFYING.value
                            and verification_until is not None
                            and verification_until > now
                        )

                        if in_verification_window:
                            # Re-trigger inside the verification window → previous remediation FAILED.
                            attempts = existing.get("remediation_attempts", 0) + 1
                            max_attempts = _cfg(server).get("max_remediation_attempts") or MAX_REMEDIATION_ATTEMPTS
                            print(f"🔁 Rule '{rule['name']}' re-fired during verification — attempt {attempts}/{max_attempts}")

                            if attempts >= max_attempts:
                                # Give up — mark exhausted, escalate, do NOT re-run.
                                await db[Collections.INCIDENTS].update_one(
                                    {"_id": existing_id},
                                    {"$set": {
                                        "status": IncidentStatus.OPEN.value,
                                        "remediation_attempts": attempts,
                                        "automation_failure_reason": AutomationFailureReason.REMEDIATION_EXHAUSTED.value,
                                        "verification_until": None,
                                        "description": existing["description"] + f" (Auto-remediation failed {attempts}x)",
                                    }},
                                )
                                event_bus.emit(WSTopic.INCIDENTS, "incident.updated", {
                                    "incident_id": str(existing_id),
                                    "server_id": server_id_str,
                                    "reason": AutomationFailureReason.REMEDIATION_EXHAUSTED.value,
                                })
                                event_bus.emit(f"servers.{server_id_str}.incidents", "incident.updated", {  # deprecated: remove when RBAC lands
                                    "incident_id": str(existing_id),
                                    "server_id": server_id_str,
                                    "reason": AutomationFailureReason.REMEDIATION_EXHAUSTED.value,
                                })
                                await notify(
                                    type=NotificationType.REMEDIATION_FAILED,
                                    category=NotificationCategory.AUTOMATION,
                                    severity=NotificationSeverity.ERROR,
                                    title="Auto-remediation exhausted",
                                    body=f"'{rule['name']}' could not be fixed automatically after {attempts} attempts.",
                                    link=f"/incidents/{existing_id}",
                                    server_id=server_id_str,
                                    entity_type="incident",
                                    entity_id=str(existing_id),
                                )
                                escalation_payload = AlertPayload(
                                    incident_id=str(existing_id),
                                    server_id=server_id_str,
                                    server_hostname=server.get("hostname", server.get("ip_address", "unknown")),
                                    server_ip=server.get("ip_address", "unknown"),
                                    rule_name=rule["name"],
                                    severity=rule["severity"],
                                    description=f"Auto-remediation exhausted: {rule['name']}",
                                    context=existing.get("context", extracted_context),
                                    detected_at=now,
                                    action_level=action_level,
                                    remediation_status="exhausted",
                                    is_escalation=True,
                                    remediation_attempts=attempts,
                                )
                                await self.notification_service.send_alert(escalation_payload)
                                continue

                            # Still under the limit — retry the same script with the original context.
                            await db[Collections.INCIDENTS].update_one(
                                {"_id": existing_id},
                                {"$set": {
                                    "remediation_attempts": attempts,
                                    "last_remediation_at": now,
                                    "verification_until": now + timedelta(minutes=_cfg(server).get("verification_window_minutes") or VERIFICATION_WINDOW_MINUTES),
                                    "status": IncidentStatus.VERIFYING.value,
                                }},
                            )
                            event_bus.emit(WSTopic.INCIDENTS, "incident.updated", {
                                "incident_id": str(existing_id),
                                "server_id": server_id_str,
                                "reason": "remediation_retry",
                                "attempt": attempts,
                            })
                            event_bus.emit(f"servers.{server_id_str}.incidents", "incident.updated", {  # deprecated: remove when RBAC lands
                                "incident_id": str(existing_id),
                                "server_id": server_id_str,
                                "reason": "remediation_retry",
                                "attempt": attempts,
                            })

                            if candidate_script_id:
                                await self.automation_service.execute_remediation(
                                    server_id=server_id_str,
                                    script_id=candidate_script_id,
                                    incident_id=str(existing_id),
                                    variables=existing.get("context", extracted_context),
                                )
                            continue

                        # Existing OPEN/VERIFYING but verification window already expired — standard dedup.
                        continue

                    # ========================================================
                    # No prior recent incident — fresh detection.
                    # ========================================================
                    print(f"🚨 Incident: {rule['name']} | Ctx: {extracted_context}")

                    incident = IncidentInDB(
                        server_id=server_id_str,
                        rule_id=rule_id_str,
                        log_id=str(log["_id"]),
                        severity=rule["severity"],
                        description=f"Detected: {rule['name']}",
                        context=extracted_context,
                    )

                    # Check if script is enabled (only relevant for L1/L2)
                    skipped_reason = None
                    if action_level in [1, 2] and candidate_script_id:
                        try:
                            script_doc = await db[Collections.SCRIPTS].find_one({"_id": ObjectId(candidate_script_id)})
                        except Exception:
                            script_doc = None
                        if not script_doc:
                            skipped_reason = AutomationSkippedReason.SCRIPT_MISSING.value
                        elif not script_doc.get("enabled", True):
                            skipped_reason = AutomationSkippedReason.SCRIPT_DISABLED.value
                        elif server_id_str in (script_doc.get("disabled_for_servers") or []):
                            # Phase 28.4 — operator approved an AI suggestion to
                            # disable this script on this server only. Rule still
                            # fires (so the operator sees the incident), but
                            # automation is skipped and the rule degrades to alert.
                            skipped_reason = AutomationSkippedReason.SCRIPT_DISABLED_FOR_SERVER.value

                    # Recurrence check — has the same script "fixed" this on this server
                    # repeatedly without lasting effect? Count consecutive auto-resolved
                    # → recurrence cycles. When the streak reaches the threshold, pause
                    # automation and alert (treated as skipped_reason path).
                    recurrence_streak = 0
                    if action_level in [1, 2] and candidate_script_id and not skipped_reason:
                        recurrence_threshold = _cfg(server).get("recurrence_streak_threshold") or RECURRENCE_STREAK_THRESHOLD
                        recurrence_lookback_h = _cfg(server).get("recurrence_lookback_hours") or RECURRENCE_LOOKBACK_HOURS
                        recurrence_cutoff = now - timedelta(hours=recurrence_lookback_h)

                        last_resolved = await db[Collections.INCIDENTS].find_one(
                            {
                                "server_id": server_id_str,
                                "rule_id": rule_id_str,
                                "status": IncidentStatus.RESOLVED.value,
                                "detected_at": {"$gte": recurrence_cutoff},
                            },
                            sort=[("detected_at", -1)],
                        )
                        if last_resolved:
                            recurrence_streak = (last_resolved.get("recurrence_streak") or 0) + 1

                        if recurrence_streak >= recurrence_threshold:
                            skipped_reason = AutomationSkippedReason.RECURRENCE_DETECTED.value
                            print(f"🔄 Recurrence streak {recurrence_streak}/{recurrence_threshold} for '{rule['name']}' on {server.get('hostname')} — pausing automation")

                    alert_payload = AlertPayload(
                        incident_id="",
                        server_id=server_id_str,
                        server_hostname=server.get("hostname", server.get("ip_address", "unknown")),
                        server_ip=server.get("ip_address", "unknown"),
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        description=f"Detected: {rule['name']}",
                        context=extracted_context,
                        detected_at=now,
                        action_level=action_level,
                    )

                    if action_level in [1, 2] and candidate_script_id and not skipped_reason:
                        # Run remediation — incident enters VERIFYING state.
                        # If the rule re-fires within VERIFICATION_WINDOW_MINUTES, the
                        # background job_verify_remediation will not auto-resolve and the
                        # next analyze_logs() call will retry/escalate via the branch above.
                        print(f"⚙️ Triggering Automation for Rule: {rule['name']}")

                        incident_data = incident.model_dump()
                        incident_data["status"] = IncidentStatus.VERIFYING.value
                        incident_data["remediation_attempts"] = 1
                        incident_data["last_remediation_at"] = now
                        incident_data["verification_until"] = now + timedelta(minutes=_cfg(server).get("verification_window_minutes") or VERIFICATION_WINDOW_MINUTES)
                        incident_data["recurrence_streak"] = recurrence_streak
                        inc_result = await db[Collections.INCIDENTS].insert_one(incident_data)
                        incident_id = str(inc_result.inserted_id)
                        await db[Collections.SERVERS].update_one(
                            {"_id": ObjectId(server_id_str)},
                            {"$inc": {"open_incidents_count": 1}},
                        )
                        event_bus.emit(WSTopic.SERVERS, "server.updated", {"server_id": server_id_str})

                        event_bus.emit(WSTopic.INCIDENTS, "incident.created", {
                            "incident_id": incident_id,
                            "server_id": server_id_str,
                            "severity": rule["severity"],
                            "rule_name": rule["name"],
                            "action_level": action_level,
                        })
                        event_bus.emit(f"servers.{server_id_str}.incidents", "incident.created", {  # deprecated: remove when RBAC lands
                            "incident_id": incident_id,
                            "server_id": server_id_str,
                            "severity": rule["severity"],
                            "rule_name": rule["name"],
                            "action_level": action_level,
                        })
                        event_bus.emit(WSTopic.DASHBOARD_SUMMARY, "incident.created", {"incident_id": incident_id})
                        await _notify_incident_created(incident_id, server_id_str, rule["severity"], rule["name"])

                        success = await self.automation_service.execute_remediation(
                            server_id=server_id_str,
                            script_id=candidate_script_id,
                            incident_id=incident_id,
                            variables=extracted_context,
                        )

                        # Execution failure — keep VERIFYING + window intact so the retry
                        # path fires if the rule re-triggers within the window. Clearing
                        # VERIFYING here would permanently block retries (Bug 2).
                        # Annotate the failure reason for operator visibility.
                        if not success:
                            await db[Collections.INCIDENTS].update_one(
                                {"_id": inc_result.inserted_id},
                                {"$set": {"automation_failure_reason": AutomationFailureReason.EXECUTION_FAILED.value}},
                            )

                        # Alert on all action levels, success or failure.
                        alert_payload.incident_id = incident_id
                        alert_payload.remediation_status = "executed" if success else "failed"
                        await self.notification_service.send_alert(alert_payload)

                    elif action_level in [1, 2] and skipped_reason:
                        # Script disabled/missing/recurrence_detected — degrade to alert-only.
                        incident_data = incident.model_dump()
                        incident_data["automation_skipped_reason"] = skipped_reason
                        incident_data["recurrence_streak"] = recurrence_streak
                        inc_result = await db[Collections.INCIDENTS].insert_one(incident_data)
                        incident_id = str(inc_result.inserted_id)
                        await db[Collections.SERVERS].update_one(
                            {"_id": ObjectId(server_id_str)},
                            {"$inc": {"open_incidents_count": 1}},
                        )
                        event_bus.emit(WSTopic.SERVERS, "server.updated", {"server_id": server_id_str})
                        print(f"⚠️ Automation skipped ({skipped_reason}) for rule: {rule['name']}")
                        event_bus.emit(WSTopic.INCIDENTS, "incident.created", {
                            "incident_id": incident_id,
                            "server_id": server_id_str,
                            "severity": rule["severity"],
                            "rule_name": rule["name"],
                            "action_level": 3,
                        })
                        event_bus.emit(f"servers.{server_id_str}.incidents", "incident.created", {  # deprecated: remove when RBAC lands
                            "incident_id": incident_id,
                            "server_id": server_id_str,
                            "severity": rule["severity"],
                            "rule_name": rule["name"],
                            "action_level": 3,
                        })
                        event_bus.emit(WSTopic.DASHBOARD_SUMMARY, "incident.created", {"incident_id": incident_id})
                        await _notify_incident_created(incident_id, server_id_str, rule["severity"], rule["name"])
                        alert_payload.incident_id = incident_id
                        alert_payload.remediation_status = "skipped"
                        await self.notification_service.send_alert(alert_payload)

                    else:
                        # L3 (alert-only) or no script linked.
                        # Same-batch dedup: skip if this (server, rule) pair was
                        # already queued earlier in this analyze_logs() call.
                        dedup_key = (server_id_str, rule_id_str)
                        if dedup_key not in _batch_l3_keys:
                            _batch_l3_keys.add(dedup_key)
                            inc_data = incident.model_dump()
                            inc_data["recurrence_streak"] = 0  # L3 never runs a script
                            new_incidents.append(inc_data)

            # ── Tier 2: heuristic fallback for logs that no rule matched ──
            if not matched_any:
                try:
                    flags = await self.heuristic_service.evaluate(log, server)
                    if flags:
                        await self.anomalies_service.record_log_observation(
                            log=log, server=server, flags=flags
                        )
                except Exception as e:
                    # Heuristics must never break detection — log and move on
                    print(f"⚠️ Heuristic evaluation failed: {e}")

        # 4. Bulk Save (for incidents that didn't run automation)
        if new_incidents:
            inc_results = await db[Collections.INCIDENTS].insert_many(new_incidents)
            print(f"💾 Saved {len(new_incidents)} new incidents.")

            # Increment open_incidents_count per server (one $inc per distinct server_id)
            _sid_counts: dict[str, int] = {}
            for inc_data in new_incidents:
                _sid_counts[inc_data["server_id"]] = _sid_counts.get(inc_data["server_id"], 0) + 1
            for _sid_str, _delta in _sid_counts.items():
                await db[Collections.SERVERS].update_one(
                    {"_id": ObjectId(_sid_str)},
                    {"$inc": {"open_incidents_count": _delta}},
                )
                event_bus.emit(WSTopic.SERVERS, "server.updated", {"server_id": _sid_str})

            for i, inc_data in enumerate(new_incidents):
                _sid = inc_data["server_id"]
                event_bus.emit(WSTopic.INCIDENTS, "incident.created", {
                    "incident_id": str(inc_results.inserted_ids[i]),
                    "server_id": _sid,
                    "severity": inc_data.get("severity"),
                    "rule_name": inc_data["description"].replace("Detected: ", ""),
                    "action_level": 3,
                })
                event_bus.emit(f"servers.{_sid}.incidents", "incident.created", {  # deprecated: remove when RBAC lands
                    "incident_id": str(inc_results.inserted_ids[i]),
                    "server_id": _sid,
                    "severity": inc_data.get("severity"),
                    "rule_name": inc_data["description"].replace("Detected: ", ""),
                    "action_level": 3,
                })
                await _notify_incident_created(
                    str(inc_results.inserted_ids[i]),
                    _sid,
                    inc_data.get("severity"),
                    inc_data["description"].replace("Detected: ", ""),
                )
            event_bus.emit(WSTopic.DASHBOARD_SUMMARY, "incidents.bulk_created", {
                "count": len(new_incidents),
            })

            # 5. Send notifications for Level 3 (alert-only) incidents
            for i, inc_data in enumerate(new_incidents):
                action_level = 3  # These are the non-automated ones
                alert_payload = AlertPayload(
                    incident_id=str(inc_results.inserted_ids[i]),
                    server_id=inc_data["server_id"],
                    server_hostname=server.get("hostname", server.get("ip_address", "unknown")),
                    server_ip=server.get("ip_address", "unknown"),
                    rule_name=inc_data["description"].replace("Detected: ", ""),
                    severity=inc_data["severity"],
                    description=inc_data["description"],
                    context=inc_data.get("context", {}),
                    detected_at=datetime.now(timezone.utc),
                    action_level=action_level,
                )
                await self.notification_service.send_alert(alert_payload)

    # seed_default_rules removed — use `python seed.py` to populate defaults.
    async def _seed_default_rules_removed(self):
        """
        Ensures default rules exist. Safe to call on every startup — only
        inserts rules whose name is not already in the collection, so
        user-created or user-modified rules are never overwritten.
        """
        db = get_database()

        # --- Build a name→id lookup from seeded scripts ---
        scripts = await db[Collections.SCRIPTS].find().to_list(length=100)
        script_lookup = {s["name"]: str(s["_id"]) for s in scripts}

        default_rules = [
            # ==============================
            # LINUX SECURITY & SYSTEM
            # ==============================
            {
                "name": "SSH Brute Force / Failed Login",
                "pattern": r"(?i)(?:failed password|authentication failure|invalid user)\s+for\s+(?P<username>\S+)\s+from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})",
                "severity": "medium",
                "action_level": 2,
                "enabled": True,
                "os_type": "linux",
                "tags": ["security", "auth", "ssh"],
                "remediation_script_name": "Block IP (iptables)",
            },
            {
                "name": "Sudo Abuse",
                "pattern": r"(?i)sudo:\s+(?P<username>\S+)\s*:\s*(?:command not found|incorrect password|user NOT in sudoers)",
                "severity": "medium",
                "action_level": 2,
                "enabled": True,
                "os_type": "linux",
                "tags": ["security", "privilege"],
            },
            {
                "name": "Root Login Detection",
                "pattern": r"(?i)accepted password for root|session opened for user root",
                "severity": "high",
                "action_level": 2,
                "enabled": True,
                "os_type": "linux",
                "tags": ["security", "root"],
            },
            {
                "name": "Out of Memory (OOM) Killer",
                "pattern": r"(?i)(?:Out of memory|Kill process)\s+(?P<process_id>\d+)\s+\((?P<process_name>\S+)\)",
                "severity": "critical",
                "action_level": 2,
                "enabled": True,
                "os_type": "linux",
                "tags": ["system", "stability", "memory"],
                "remediation_script_name": "Kill Process by PID",
            },
            {
                "name": "Disk Space Critical",
                "pattern": r"(?i)(No space left on device|I/O error|EXT4-fs error)",
                "severity": "critical",
                "action_level": 2,
                "enabled": True,
                "os_type": "linux",
                "tags": ["system", "storage"],
                "remediation_script_name": "Clear Temp Files",
            },
            {
                "name": "New User Creation",
                "pattern": r"(?i)(?:new user|new group): name=(?P<username>\S+)",
                "severity": "medium",
                "action_level": 3,
                "enabled": True,
                "os_type": "linux",
                "tags": ["security", "persistence"],
            },

            # ==============================
            # WINDOWS SECURITY & SYSTEM
            # ==============================
            {
                "name": "Windows Failed Logon",
                "pattern": r"(?i)(?:audit failure|an account failed to log on|event id 4625)",
                "severity": "medium",
                "action_level": 2,
                "enabled": True,
                "os_type": "windows",
                "tags": ["security", "auth"],
                "remediation_script_name": "Block IP (Windows Firewall)",
            },
            {
                "name": "Windows Defender Malware Detected",
                "pattern": r"(?i)(?:windows defender|antimalware).*(?:detected|malware|threat)",
                "severity": "critical",
                "action_level": 3,
                "enabled": True,
                "os_type": "windows",
                "tags": ["security", "malware"],
            },
            {
                "name": "Windows Service Crash",
                "pattern": r"(?i)(?:service terminated unexpectedly|service hung|event id 7034)",
                "severity": "high",
                "action_level": 2,
                "enabled": True,
                "os_type": "windows",
                "tags": ["system", "stability"],
                "remediation_script_name": "Restart Service (Windows)",
            },
            {
                "name": "Suspicious PowerShell Execution",
                "pattern": r"(?i)(?:powershell).*(?:bypass|hidden|encodedcommand|downloadstring)",
                "severity": "high",
                "action_level": 2,
                "enabled": True,
                "os_type": "windows",
                "tags": ["security", "execution"],
            },
            {
                "name": "Windows Security Log Cleared",
                "pattern": r"(?i)(?:audit log was cleared|event id 1102)",
                "severity": "critical",
                "action_level": 2,
                "enabled": True,
                "os_type": "windows",
                "tags": ["security", "evasion"],
            },

            # ==============================
            # COMMON / WEB / ATTACKS
            # ==============================
            {
                "name": "Web Server 500 Error Flood",
                "pattern": r"HTTP\/1\.[01].*\" 50[0-9] ",
                "severity": "medium",
                "action_level": 3,
                "enabled": True,
                "os_type": "common",
                "tags": ["app", "web"],
            },
            {
                "name": "SQL Injection Attempt",
                "pattern": r"(?i)(union select|OR 1=1|drop table|information_schema|waitfor delay)",
                "severity": "critical",
                "action_level": 2,
                "enabled": True,
                "os_type": "common",
                "tags": ["security", "web", "sqli"],
                "remediation_script_name": "Block IP (iptables)",
            },
            {
                "name": "Simulated Attack",
                "pattern": "Hacking Attempt",
                "severity": "critical",
                "action_level": 1,
                "enabled": True,
                "os_type": "common",
                "tags": ["test"],
                "remediation_script_name": "Block IP (iptables)",
            },
        ]

        # --- Resolve script names to IDs and stamp timestamps ---
        now = datetime.now(timezone.utc)
        for rule in default_rules:
            script_name = rule.pop("remediation_script_name", None)
            if script_name and script_name in script_lookup:
                rule["remediation_script_id"] = script_lookup[script_name]
            rule.setdefault("created_at", now)
            rule.setdefault("updated_at", None)

        # Only insert rules that don't already exist by name
        existing_names = {
            r["name"]
            for r in await db[Collections.RULES].find({}, projection={"name": 1}).to_list(length=1000)
        }
        missing = [r for r in default_rules if r["name"] not in existing_names]

        if missing:
            await db[Collections.RULES].insert_many(missing)
            linked_count = sum(1 for r in missing if r.get("remediation_script_id"))
            print(f"🌱 Seeded {len(missing)} missing rule(s) ({linked_count} linked to scripts)")
        else:
            print(f"✅ Rules up-to-date ({len(existing_names)} rules in DB)")