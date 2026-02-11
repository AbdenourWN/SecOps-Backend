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
        except:
            return None

    async def execute_remediation(self, server_id: str, script_id: str, incident_id: str):
        """
        The Heavy Lifter.
        1. Fetches Script & Server.
        2. Connects via Executor.
        3. Runs Code.
        4. Logs Result.
        """
        db = get_database()
        
        # 1. Fetch Data
        script_doc = await self.get_script(script_id)
        if not script_doc:
            print(f"❌ Script {script_id} not found!")
            return False

        server = await db["servers"].find_one({"_id": ObjectId(server_id)})
        if not server: return False

        # 2. Prepare Credentials & Executor
        cred = await db["credentials"].find_one({"_id": ObjectId(server["credential_id"])})
        plain_secret = decrypt_password(cred["encrypted_secret"])
        
        executor = get_server_executor(server, plain_secret)
        executor.credential['username'] = cred['username']

        print(f"🤖 AUTO-FIX: Executing '{script_doc['name']}' on {server['hostname']}...")

        # 3. Execution Logic
        # For now, we assume simple one-line commands or small scripts.
        # Complex scripts might need file upload first, but let's stick to simple execution.
        command = script_doc["content"]
        
        # (Optional: In the future, we replace variables here like {{IP}})
        
        result = await executor.run_command(command)
        
        # 4. Audit Log (Save to DB)
        audit_log = AutomationLog(
            incident_id=incident_id,
            script_id=script_id,
            server_id=server_id,
            status=result["status"],
            output=result.get("output"),
            error=result.get("error")
        )
        await db["automation_logs"].insert_one(audit_log.model_dump())
        
        if result["status"] == "success":
            print(f"✅ Remediation Successful: {result.get('output')}")
            return True
        else:
            print(f"❌ Remediation Failed: {result.get('error')}")
            return False