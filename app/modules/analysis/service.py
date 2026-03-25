import re
from app.core.database import get_database
from app.modules.analysis.schemas import IncidentInDB, ActionLevel, IncidentStatus
from app.modules.logs.schemas import LogEntryInDB
from bson import ObjectId
from app.modules.automation.service import AutomationService

class AnalysisService:

    def __init__(self):
        self.automation_service = AutomationService()

    async def analyze_logs(self, logs: list[dict]):
        """
        The Core Logic:
        1. Fetch all enabled Rules from DB.
        2. Check every log against every rule.
        3. Create Incidents if matches found.
        """
        if not logs:
            return

        db = get_database()

        # 1. OPTIMIZATION: Fetch Server OS once
        # (Assuming all logs in this batch belong to the same server)
        first_server_id = logs[0]["server_id"]
        server = await db["servers"].find_one({"_id": ObjectId(first_server_id)})
        if not server:
            return

        server_os = server.get("os_type", "linux")

        # 2. Load Rules
        rules_cursor = db["rules"].find({"enabled": True})
        rules_data = await rules_cursor.to_list(length=200)

        if not rules_data:
            return

        # --- OPTIMIZATION: Pre-compile Regex & Filter OS ---
        # We prepare the rules BEFORE looping through logs.
        # This makes the engine much faster.
        active_rules = []
        for r in rules_data:
            # OS Filter
            if r.get("os_type", "common") != "common" and r.get("os_type") != server_os:
                continue
            
            try:
                # Compile Regex once
                active_rules.append({
                    "data": r,
                    "compiled_pattern": re.compile(r["pattern"], re.IGNORECASE)
                })
            except re.error:
                print(f"❌ Invalid Regex in Rule {r['name']}")
        # ---------------------------------------------------

        new_incidents = []

        # 3. The Matching Loop
        for log in logs:
            log_msg = log.get("message", "")

            for rule_obj in active_rules:
                rule = rule_obj["data"]
                pattern = rule_obj["compiled_pattern"]

                # Run Regex
                match = pattern.search(log_msg)
                
                if match:
                    # SMART EXTRACTION 🧠
                    extracted_context = match.groupdict()
                    if not extracted_context:
                        extracted_context = {"raw_match": match.group(0)}

                    print(f"🚨 Incident: {rule['name']} | Ctx: {extracted_context}")

                    # Create Incident Object
                    incident = IncidentInDB(
                        server_id=str(log["server_id"]),
                        rule_id=str(rule["_id"]),
                        log_id=str(log["_id"]),
                        severity=rule["severity"],
                        description=f"Detected: {rule['name']}",
                        context=extracted_context # Save vars to DB
                    )

                    # CHECK LEVEL & AUTOMATION
                    action_level = rule.get("action_level", 3)
                    remediation_script_id = rule.get("remediation_script_id")

                    executed_fix = False

                    # If Level 1 (Auto) or Level 2 (Fix+Alert) AND we have a script
                    if action_level in [1, 2] and remediation_script_id:
                        print(f"⚙️ Triggering Automation for Rule: {rule['name']}")

                        # Insert incident FIRST to get an ID
                        inc_result = await db["incidents"].insert_one(incident.model_dump())
                        incident_id = str(inc_result.inserted_id)

                        # Execute Script
                        # FIX: We pass the 'extracted_context' as variables!
                        success = await self.automation_service.execute_remediation(
                            server_id=str(log["server_id"]),
                            script_id=remediation_script_id,
                            incident_id=incident_id,
                            variables=extracted_context # <--- CRITICAL FIX
                        )

                        # If Auto-Fix (Level 1) worked, verify and close incident
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
                    else:
                        # Just save the incident normally via bulk list
                        new_incidents.append(incident.model_dump())

        # 4. Bulk Save (for incidents that didn't run automation)
        if new_incidents:
            await db["incidents"].insert_many(new_incidents)
            print(f"💾 Saved {len(new_incidents)} new incidents.")

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