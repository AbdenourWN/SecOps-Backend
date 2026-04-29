import re
import time
from datetime import datetime, timezone, timedelta
from app.core.database import get_database
from app.modules.analysis.schemas import IncidentInDB, ActionLevel, IncidentStatus
from app.modules.logs.schemas import LogEntryInDB
from bson import ObjectId
from app.modules.automation.service import AutomationService
from app.modules.notifications.service import NotificationService
from app.modules.notifications.schemas import AlertPayload
from app.modules.heuristics.service import HeuristicService
from app.modules.anomalies.service import AnomaliesService
from app.core.events import event_bus

# ========================================================================
# Remediation Verification Tunables
# ========================================================================
# After a remediation runs we wait this long before declaring success.
# If the same rule re-fires on the same server within this window, the
# remediation didn't work.
VERIFICATION_WINDOW_MINUTES = 10
# How many times we retry the same script before giving up and escalating.
MAX_REMEDIATION_ATTEMPTS = 3
# An open/verifying incident older than this is considered stale; a new
# incident is opened instead of being treated as a recurrence.
RECENT_INCIDENT_LOOKBACK_MINUTES = 30

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
        rules_data = await db["rules"].find({"enabled": True}).to_list(length=200)
        
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
        server = await db["servers"].find_one({"_id": ObjectId(first_server_id)})
        if not server:
            return

        server_os = server.get("os_type", "linux")

        # 2. OPT-4: Get rules from cache (no DB query if cache is fresh)
        all_rules = await _get_cached_rules()

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

                    action_level = rule.get("action_level", 3)

                    # Pick OS-appropriate script ID
                    if server_os == "windows" and rule.get("remediation_script_id_windows"):
                        candidate_script_id = rule["remediation_script_id_windows"]
                    else:
                        candidate_script_id = rule.get("remediation_script_id")

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
                    lookback_cutoff = now - timedelta(minutes=RECENT_INCIDENT_LOOKBACK_MINUTES)
                    existing = await db["incidents"].find_one(
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
                        if existing.get("automation_failure_reason") == "remediation_exhausted":
                            continue

                        verification_until = existing.get("verification_until")
                        in_verification_window = (
                            existing.get("status") == IncidentStatus.VERIFYING.value
                            and verification_until is not None
                            and verification_until > now
                        )

                        if in_verification_window:
                            # Re-trigger inside the verification window → previous remediation FAILED.
                            attempts = existing.get("remediation_attempts", 0) + 1
                            print(f"🔁 Rule '{rule['name']}' re-fired during verification — attempt {attempts}/{MAX_REMEDIATION_ATTEMPTS}")

                            if attempts >= MAX_REMEDIATION_ATTEMPTS:
                                # Give up — mark exhausted, escalate, do NOT re-run.
                                await db["incidents"].update_one(
                                    {"_id": existing_id},
                                    {"$set": {
                                        "status": IncidentStatus.OPEN.value,
                                        "remediation_attempts": attempts,
                                        "automation_failure_reason": "remediation_exhausted",
                                        "verification_until": None,
                                        "description": existing["description"] + f" (Auto-remediation failed {attempts}x)",
                                    }},
                                )
                                event_bus.emit("incidents", "incident.updated", {
                                    "incident_id": str(existing_id),
                                    "server_id": server_id_str,
                                    "reason": "remediation_exhausted",
                                })
                                event_bus.emit(f"servers.{server_id_str}.incidents", "incident.updated", {  # deprecated: remove when RBAC lands
                                    "incident_id": str(existing_id),
                                    "server_id": server_id_str,
                                    "reason": "remediation_exhausted",
                                })
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
                            await db["incidents"].update_one(
                                {"_id": existing_id},
                                {"$set": {
                                    "remediation_attempts": attempts,
                                    "last_remediation_at": now,
                                    "verification_until": now + timedelta(minutes=VERIFICATION_WINDOW_MINUTES),
                                    "status": IncidentStatus.VERIFYING.value,
                                }},
                            )
                            event_bus.emit("incidents", "incident.updated", {
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
                            script_doc = await db["scripts"].find_one({"_id": ObjectId(candidate_script_id)})
                        except Exception:
                            script_doc = None
                        if not script_doc:
                            skipped_reason = "script_missing"
                        elif not script_doc.get("enabled", True):
                            skipped_reason = "script_disabled"

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
                        incident_data["verification_until"] = now + timedelta(minutes=VERIFICATION_WINDOW_MINUTES)
                        inc_result = await db["incidents"].insert_one(incident_data)
                        incident_id = str(inc_result.inserted_id)

                        event_bus.emit("incidents", "incident.created", {
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
                        event_bus.emit("dashboard.summary", "incident.created", {"incident_id": incident_id})

                        success = await self.automation_service.execute_remediation(
                            server_id=server_id_str,
                            script_id=candidate_script_id,
                            incident_id=incident_id,
                            variables=extracted_context,
                        )

                        # Hard execution failure (exit != 0) — drop verification, surface as OPEN.
                        if not success:
                            await db["incidents"].update_one(
                                {"_id": inc_result.inserted_id},
                                {"$set": {
                                    "status": IncidentStatus.OPEN.value,
                                    "verification_until": None,
                                }},
                            )

                        # Alert on all action levels, success or failure.
                        alert_payload.incident_id = incident_id
                        alert_payload.remediation_status = "executed" if success else "failed"
                        await self.notification_service.send_alert(alert_payload)

                    elif action_level in [1, 2] and skipped_reason:
                        # Script disabled/missing — degrade to alert-only.
                        incident_data = incident.model_dump()
                        incident_data["automation_skipped_reason"] = skipped_reason
                        inc_result = await db["incidents"].insert_one(incident_data)
                        incident_id = str(inc_result.inserted_id)
                        print(f"⚠️ Automation skipped ({skipped_reason}) for rule: {rule['name']}")
                        event_bus.emit("incidents", "incident.created", {
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
                        event_bus.emit("dashboard.summary", "incident.created", {"incident_id": incident_id})
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
                            new_incidents.append(incident.model_dump())

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
            inc_results = await db["incidents"].insert_many(new_incidents)
            print(f"💾 Saved {len(new_incidents)} new incidents.")

            for i, inc_data in enumerate(new_incidents):
                _sid = inc_data["server_id"]
                event_bus.emit("incidents", "incident.created", {
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
            event_bus.emit("dashboard.summary", "incidents.bulk_created", {
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
        scripts = await db["scripts"].find().to_list(length=100)
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
            for r in await db["rules"].find({}, projection={"name": 1}).to_list(length=1000)
        }
        missing = [r for r in default_rules if r["name"] not in existing_names]

        if missing:
            await db["rules"].insert_many(missing)
            linked_count = sum(1 for r in missing if r.get("remediation_script_id"))
            print(f"🌱 Seeded {len(missing)} missing rule(s) ({linked_count} linked to scripts)")
        else:
            print(f"✅ Rules up-to-date ({len(existing_names)} rules in DB)")