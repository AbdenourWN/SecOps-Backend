import re
from app.core.database import get_database
from app.modules.automation.schemas import ScriptCreate, ScriptInDB, AutomationLog
from app.core.executors import get_server_executor
from app.core.security import decrypt_password
from bson import ObjectId
from datetime import datetime, timezone


class AutomationService:

    async def create_script(self, script: ScriptCreate):
        db = get_database()
        new_script = script.model_dump()
        new_script["created_at"] = datetime.now(timezone.utc)
        new_script["updated_at"] = datetime.now(timezone.utc)

        result = await db["scripts"].insert_one(new_script)
        return str(result.inserted_id)

    async def get_script(self, script_id: str):
        db = get_database()
        try:
            return await db["scripts"].find_one({"_id": ObjectId(script_id)})
        except Exception:
            return None

    def _substitute_variables(self, template: str, variables: dict) -> str:
        """
        Replaces {{key}} placeholders in the script content with actual values.
        Example: "iptables -A INPUT -s {{source_ip}} -j DROP"
                 with variables={"source_ip": "1.2.3.4"}
                 becomes "iptables -A INPUT -s 1.2.3.4 -j DROP"
        """
        if not variables:
            return template

        def replacer(match):
            key = match.group(1).strip()
            return str(variables.get(key, match.group(0)))  # Keep original if key not found

        return re.sub(r"\{\{(\s*\w+\s*)\}\}", replacer, template)

    async def execute_remediation(
        self,
        server_id: str,
        script_id: str,
        incident_id: str,
        variables: dict = None,
    ):
        """
        The Heavy Lifter.
        1. Fetches Script & Server.
        2. Connects via Executor.
        3. Substitutes variables (e.g. {{source_ip}}).
        4. Runs Code.
        5. Logs Result.
        """
        db = get_database()

        # 1. Fetch Data
        script_doc = await self.get_script(script_id)
        if not script_doc:
            print(f"❌ Script {script_id} not found!")
            return False

        server = await db["servers"].find_one({"_id": ObjectId(server_id)})
        if not server:
            return False

        # 2. Prepare Credentials & Executor
        cred = await db["credentials"].find_one(
            {"_id": ObjectId(server["credential_id"])}
        )
        plain_secret = decrypt_password(cred["encrypted_secret"])

        executor = get_server_executor(server, plain_secret)
        executor.credential["username"] = cred["username"]

        print(f"🤖 AUTO-FIX: Executing '{script_doc['name']}' on {server['hostname']}...")

        # 3. Variable Substitution
        command = script_doc["content"]
        command = self._substitute_variables(command, variables or {})

        print(f"📝 Resolved Command: {command}")

        # 4. Execute
        result = await executor.run_command(command)

        # 5. Audit Log (Save to DB)
        audit_log = AutomationLog(
            incident_id=incident_id,
            script_id=script_id,
            server_id=server_id,
            status=result["status"],
            output=result.get("output"),
            error=result.get("error"),
        )
        await db["automation_logs"].insert_one(audit_log.model_dump())

        if result["status"] == "success":
            print(f"✅ Remediation Successful: {result.get('output')}")
            return True
        else:
            print(f"❌ Remediation Failed: {result.get('error')}")
            return False

    async def seed_default_scripts(self):
        """
        Pre-loads practical remediation scripts into the database.
        Run once on startup (skips if scripts already exist).
        """
        db = get_database()
        if await db["scripts"].count_documents({}) > 0:
            return

        default_scripts = [
            # ============= LINUX =============
            {
                "name": "Block IP (iptables)",
                "description": "Blocks an IP address using iptables firewall rules.",
                "language": "bash",
                "target_os": "linux",
                "content": "iptables -A INPUT -s {{source_ip}} -j DROP && echo 'Blocked {{source_ip}}'",
            },
            {
                "name": "Restart Service (systemctl)",
                "description": "Restarts a Linux service via systemctl.",
                "language": "bash",
                "target_os": "linux",
                "content": "systemctl restart {{service_name}} && systemctl status {{service_name}} --no-pager",
            },
            {
                "name": "Kill Process by PID",
                "description": "Force kills a process by its PID.",
                "language": "bash",
                "target_os": "linux",
                "content": "kill -9 {{process_id}} && echo 'Killed process {{process_id}}'",
            },
            {
                "name": "Clear Temp Files",
                "description": "Removes temp files older than 7 days to free disk space.",
                "language": "bash",
                "target_os": "linux",
                "content": "find /tmp -type f -mtime +7 -delete && echo 'Cleaned /tmp' && df -h /",
            },
            # ============= WINDOWS =============
            {
                "name": "Block IP (Windows Firewall)",
                "description": "Blocks an IP using Windows Firewall.",
                "language": "powershell",
                "target_os": "windows",
                "content": "New-NetFirewallRule -DisplayName 'SecOps Block {{source_ip}}' -Direction Inbound -Action Block -RemoteAddress {{source_ip}}; Write-Output 'Blocked {{source_ip}}'",
            },
            {
                "name": "Restart Service (Windows)",
                "description": "Restarts a Windows service.",
                "language": "powershell",
                "target_os": "windows",
                "content": "Restart-Service -Name '{{service_name}}' -Force; Get-Service -Name '{{service_name}}'",
            },
        ]

        # Add timestamps
        now = datetime.now(timezone.utc)
        for script in default_scripts:
            script["created_at"] = now
            script["updated_at"] = now

        await db["scripts"].insert_many(default_scripts)
        print(f"🌱 Default Scripts Seeded ({len(default_scripts)} scripts)")