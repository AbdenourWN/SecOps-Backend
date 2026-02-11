import re
from app.core.database import get_database
from app.modules.analysis.schemas import IncidentInDB
from app.modules.logs.schemas import LogEntryInDB
from bson import ObjectId

from app.modules.automation.service import AutomationService
from app.modules.analysis.schemas import ActionLevel, IncidentStatus


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

        # 1. Load Rules (Optimization: Cache this in memory later)
        rules_cursor = db["rules"].find({"enabled": True})
        rules = await rules_cursor.to_list(length=100)

        if not rules:
            return

        new_incidents = []

        # 2. The Matching Loop
        for log in logs:
            # We skip INFO logs for performance, unless you have specific INFO rules
            # if log['level'] == 'INFO': continue

            log_msg = log.get("message", "")

            for rule in rules:
                # Compile regex (In prod, pre-compile this outside the loop!)
                pattern = rule["pattern"]

                try:
                    if re.search(pattern, log_msg, re.IGNORECASE):
                        # MATCH FOUND! 🚨
                        print(
                            f"🚨 Incident Detected: {rule['name']} on Server {log['server_id']}"
                        )

                        # 1. Create Incident Object
                        incident = IncidentInDB(
                            server_id=str(log["server_id"]),
                            rule_id=str(rule["_id"]),
                            log_id=str(log["_id"]),
                            severity=rule["severity"],
                            description=f"Detected: {rule['name']}",
                        )

                        # 2. CHECK LEVEL & AUTOMATION
                        action_level = rule.get("action_level", 3)
                        remediation_script_id = rule.get("remediation_script_id")

                        executed_fix = False

                        # If Level 1 (Auto) or Level 2 (Fix+Alert) AND we have a script
                        if action_level in [1, 2] and remediation_script_id:
                            print(f"⚙️ Triggering Automation for Rule: {rule['name']}")

                            # We need to insert the incident FIRST to get an ID
                            inc_result = await db["incidents"].insert_one(
                                incident.model_dump()
                            )
                            incident_id = str(inc_result.inserted_id)

                            # Execute Script
                            success = await self.automation_service.execute_remediation(
                                server_id=str(log["server_id"]),
                                script_id=remediation_script_id,
                                incident_id=incident_id,
                            )

                            # If Auto-Fix (Level 1) worked, verify and close incident
                            if success and action_level == 1:
                                await db["incidents"].update_one(
                                    {"_id": inc_result.inserted_id},
                                    {
                                        "$set": {
                                            "status": IncidentStatus.RESOLVED,
                                            "description": incident.description
                                            + " (Auto-Resolved)",
                                        }
                                    },
                                )
                                executed_fix = True
                        else:
                            # Just save the incident normally
                            await db["incidents"].insert_one(incident.model_dump())

                        # Break loop?
                        # Usually Yes: One log shouldn't trigger 50 different incidents.
                        # Usually No: If it triggers "Root Login" AND "After Hours", we want both.
                        # Let's keep scanning for now.

                except re.error:
                    print(f"❌ Invalid Regex in Rule {rule['name']}")

        # 3. Save Incidents
        if new_incidents:
            await db["incidents"].insert_many(new_incidents)
            print(f"💾 Saved {len(new_incidents)} new incidents.")

    async def seed_default_rules(self):
        """
        Creates basic rules so the system isn't empty.
        Run this once on startup.
        """
        db = get_database()
        if await db["rules"].count_documents({}) > 0:
            return

        default_rules = [
            {
                "name": "SSH Failed Login",
                "pattern": "Failed password|authentication failure",
                "severity": "medium",
                "action_level": 2,  # Action + Alert
                "enabled": True,
            },
            {
                "name": "Root Login Attempt",
                "pattern": "accepted password for root|sshd.*session opened for user root",
                "severity": "high",
                "action_level": 2,
                "enabled": True,
            },
            {
                "name": "Sudo Abuse",
                "pattern": "sudo:.*command not found|sudo:.*incorrect password",
                "severity": "medium",
                "action_level": 3,  # Log Only + Alert
                "enabled": True,
            },
            {
                "name": "Simulated Attack",
                "pattern": "Hacking Attempt",
                "severity": "critical",
                "action_level": 1,  # Automatic Fix (Future)
                "enabled": True,
                "remediation_script_id":"6984af9205e39028ed491207"
            },
        ]
        await db["rules"].insert_many(default_rules)
        print("🌱 Default Rules Seeded")
