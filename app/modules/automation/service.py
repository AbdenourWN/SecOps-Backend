import re
from app.core.database import get_database
from app.modules.automation.schemas import ScriptCreate, ScriptInDB, AutomationLog
from app.core.executors import get_server_executor
from app.core.security import decrypt_password
from bson import ObjectId
from datetime import datetime, timezone
from app.core.events import event_bus


class AutomationService:

    async def create_script(self, script: ScriptCreate):
        db = get_database()
        new_script = script.model_dump()
        new_script["created_at"] = datetime.now(timezone.utc)
        new_script["updated_at"] = datetime.now(timezone.utc)

        result = await db["scripts"].insert_one(new_script)
        event_bus.emit("scripts", "script.created", {"script_id": str(result.inserted_id)})
        return str(result.inserted_id)

    async def get_script(self, script_id: str):
        db = get_database()
        try:
            return await db["scripts"].find_one({"_id": ObjectId(script_id)})
        except Exception:
            return None

    def _build_history_filter(
        self,
        status: str | None = None,
        server_id: str | None = None,
        script_id: str | None = None,
    ) -> dict:
        """Shared filter builder for history list + stats queries."""
        query: dict = {}
        if status in ("success", "failed"):
            query["status"] = status
        if server_id:
            query["server_id"] = server_id
        if script_id:
            query["script_id"] = script_id
        return query

    async def get_history(
        self,
        limit: int = 20,
        skip: int = 0,
        status: str | None = None,
        server_id: str | None = None,
        script_id: str | None = None,
    ):
        """
        Returns remediation runs (newest first), optionally filtered by status,
        server, or script. Enriched with server hostname and script name via batch
        lookups. Used by both the dashboard widget (limit only) and the dedicated
        activity page (with filters + pagination).
        """
        db = get_database()

        query = self._build_history_filter(status, server_id, script_id)

        cursor = (
            db["automation_logs"]
            .find(query)
            .sort("executed_at", -1)
            .skip(skip)
            .limit(limit)
        )
        runs = await cursor.to_list(length=limit)

        if not runs:
            return []

        # Batch lookup: server hostnames
        server_ids = list({r.get("server_id") for r in runs if r.get("server_id")})
        server_oids = []
        for sid in server_ids:
            try:
                server_oids.append(ObjectId(sid))
            except Exception:
                pass

        servers_map = {}
        if server_oids:
            server_docs = await db["servers"].find(
                {"_id": {"$in": server_oids}},
                {"hostname": 1},
            ).to_list(length=len(server_oids))
            servers_map = {str(s["_id"]): s.get("hostname", "Unknown") for s in server_docs}

        # Batch lookup: script names
        script_ids = list({r.get("script_id") for r in runs if r.get("script_id")})
        script_oids = []
        for sid in script_ids:
            try:
                script_oids.append(ObjectId(sid))
            except Exception:
                pass

        scripts_map = {}
        if script_oids:
            script_docs = await db["scripts"].find(
                {"_id": {"$in": script_oids}},
                {"name": 1},
            ).to_list(length=len(script_oids))
            scripts_map = {str(s["_id"]): s.get("name", "Unknown script") for s in script_docs}

        result = []
        for run in runs:
            run["_id"] = str(run["_id"])
            run["server_hostname"] = servers_map.get(run.get("server_id", ""), "Unknown")
            run["script_name"] = scripts_map.get(run.get("script_id", ""), "Unknown script")
            result.append(run)

        return result

    async def get_history_stats(
        self,
        status: str | None = None,
        server_id: str | None = None,
        script_id: str | None = None,
    ):
        """
        Aggregate counts for the automation history page headline stats.
        Honors the same filters as get_history so stats always match the
        user's current view. Also returns last_24h count for a freshness signal.
        """
        from datetime import timedelta

        db = get_database()
        query = self._build_history_filter(status, server_id, script_id)

        # Single aggregation: total + success + failed
        pipeline = [
            {"$match": query},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "success": {
                        "$sum": {"$cond": [{"$eq": ["$status", "success"]}, 1, 0]}
                    },
                    "failed": {
                        "$sum": {"$cond": [{"$eq": ["$status", "failed"]}, 1, 0]}
                    },
                }
            },
        ]
        agg = await db["automation_logs"].aggregate(pipeline).to_list(length=1)

        if agg:
            r = agg[0]
            total = r["total"]
            success = r["success"]
            failed = r["failed"]
        else:
            total = success = failed = 0

        # Separate count for the last 24h (same filters)
        since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        last_24h_query = {**query, "executed_at": {"$gte": since_24h}}
        last_24h = await db["automation_logs"].count_documents(last_24h_query)

        return {
            "total": total,
            "success": success,
            "failed": failed,
            "last_24h": last_24h,
            "success_rate": round((success / total) * 100, 1) if total > 0 else 0,
        }

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

        status = "success" if result["status"] == "success" else "failed"
        output = result.get("output")
        error = result.get("error")
        if server.get("os_type") == "linux":
            if status == "failed":
                error= output
                output = None

        # 5. Audit Log (Save to DB)
        audit_log = AutomationLog(
            incident_id=incident_id,
            script_id=script_id,
            server_id=server_id,
            status= status,
            output=output,
            error=error,
        )
        log_result = await db["automation_logs"].insert_one(audit_log.model_dump())

        event_bus.emit("automation.history", "remediation.executed", {
            "log_id": str(log_result.inserted_id),
            "script_id": script_id,
            "server_id": server_id,
            "incident_id": incident_id,
            "status": status,
        })

        if result["status"] == "success":
            print(f"✅ Remediation Successful: {result.get('output')}")
            return True
        else:
            print(f"❌ Remediation Failed: {result.get('error')}")
            return False

    # seed_default_scripts removed — use `python seed.py` to populate defaults.