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

        # 3. The Matching Loop
        for log in logs:
            log_msg = log.get("message") or ""

            for rule_obj in active_rules:
                rule = rule_obj["data"]
                pattern = rule_obj["compiled_pattern"]

                match = pattern.search(log_msg)
                
                if match:
                    # SMART EXTRACTION 🧠
                    extracted_context = match.groupdict()
                    if not extracted_context:
                        extracted_context = {"raw_match": match.group(0)}

                    # ========================================================
                    # OPT-5: DUPLICATE INCIDENT PREVENTION
                    # Check if an incident for this server + rule already 
                    # exists in the last 5 minutes. If so, skip it.
                    # ========================================================
                    recent_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
                    existing = await db["incidents"].find_one({
                        "server_id": str(log["server_id"]),
                        "rule_id": str(rule["_id"]),
                        "detected_at": {"$gte": recent_cutoff}
                    })
                    if existing:
                        continue  # Already reported — skip duplicate

                    print(f"🚨 Incident: {rule['name']} | Ctx: {extracted_context}")

                    # Create Incident Object
                    incident = IncidentInDB(
                        server_id=str(log["server_id"]),
                        rule_id=str(rule["_id"]),
                        log_id=str(log["_id"]),
                        severity=rule["severity"],
                        description=f"Detected: {rule['name']}",
                        context=extracted_context
                    )

                    # CHECK LEVEL & AUTOMATION
                    action_level = rule.get("action_level", 3)
                    remediation_script_id = rule.get("remediation_script_id")

                    executed_fix = False

                    # Build alert payload for notifications
                    alert_payload = AlertPayload(
                        incident_id="",  # Will be set after insert
                        server_id=str(log["server_id"]),
                        server_hostname=server.get("hostname", server.get("ip_address", "unknown")),
                        server_ip=server.get("ip_address", "unknown"),
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        description=f"Detected: {rule['name']}",
                        context=extracted_context,
                        detected_at=datetime.now(timezone.utc),
                        action_level=action_level,
                    )

                    # If Level 1 (Auto) or Level 2 (Fix+Alert) AND we have a script
                    if action_level in [1, 2] and remediation_script_id:
                        print(f"⚙️ Triggering Automation for Rule: {rule['name']}")

                        inc_result = await db["incidents"].insert_one(incident.model_dump())
                        incident_id = str(inc_result.inserted_id)

                        success = await self.automation_service.execute_remediation(
                            server_id=str(log["server_id"]),
                            script_id=remediation_script_id,
                            incident_id=incident_id,
                            variables=extracted_context
                        )

                        if success and action_level == 1:
                            await db["incidents"].update_one(
                                {"_id": inc_result.inserted_id},
                                {
                                    "$set": {
                                        "status": IncidentStatus.RESOLVED,
                                        "description": incident.description + " (Auto-Resolved)",
                                    }
                                },
                            )
                            executed_fix = True

                        # Level 2: Send notification after remediation
                        if action_level == 2:
                            alert_payload.incident_id = incident_id
                            alert_payload.remediation_status = "executed" if success else "failed"
                            await self.notification_service.send_alert(alert_payload)

                    else:
                        new_incidents.append(incident.model_dump())

        # 4. Bulk Save (for incidents that didn't run automation)
        if new_incidents:
            inc_results = await db["incidents"].insert_many(new_incidents)
            print(f"💾 Saved {len(new_incidents)} new incidents.")

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

    async def seed_default_rules(self):
        """
        Creates basic rules so the system isn't empty.
        Run this once on startup.
        Dynamically links scripts by name (scripts must be seeded first).
        """
        db = get_database()
        if await db["rules"].count_documents({}) > 0:
            return

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

        # --- Resolve script names to IDs ---
        for rule in default_rules:
            script_name = rule.pop("remediation_script_name", None)
            if script_name and script_name in script_lookup:
                rule["remediation_script_id"] = script_lookup[script_name]

        await db["rules"].insert_many(default_rules)
        
        linked_count = sum(1 for r in default_rules if r.get("remediation_script_id"))
        print(f"🌱 Default Rules Seeded ({len(default_rules)} rules, {linked_count} linked to scripts)")