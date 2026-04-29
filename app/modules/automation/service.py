import re
import shlex
from app.core.database import get_database
from app.core.executors import DEFAULT_COMMAND_TIMEOUT_S
from app.modules.automation.schemas import ScriptCreate, ScriptInDB, AutomationLog
from app.core.executors import get_server_executor
from app.core.security import decrypt_password
from bson import ObjectId
from datetime import datetime, timezone
from app.core.events import event_bus


# ---------------------------------------------------------------------------
# Placeholder validation
# ---------------------------------------------------------------------------

# Known placeholder types → strict validation pattern.
# None = trusted source (comes from the server doc, not log content).
#
# To relax username/service_name to allow apostrophes and accented chars,
# swap the allowlist pattern for this denylist:
#   re.compile(r"^[^;|&`$(){}<>!\n\r\x00]{1,64}$")
# That rejects only shell metacharacters while permitting everything else.
_PLACEHOLDER_VALIDATORS: dict[str, "re.Pattern | None"] = {
    "source_ip":    re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$"),
    "username":     re.compile(r"^[a-zA-Z0-9_\-\.@]{1,64}$"),
    "service_name": re.compile(r"^[a-zA-Z0-9_\-\.@]{1,64}$"),
    "process_id":   re.compile(r"^\d{1,7}$"),
    "hostname":     None,   # from server doc — trusted
    "os_type":      None,   # from server doc — trusted
    "raw_match":    None,   # fallback key used in L3 alerts only, never in scripts
}

# Shell/PowerShell metacharacters that should never appear in an unknown
# placeholder value captured from log content.
_DANGEROUS_CHARS_RE = re.compile(r"[;|&`$(){}<>!\n\r\x00]")


def _validate_placeholder_value(key: str, value: str) -> None:
    """Raise ValueError if `value` is unsafe for placeholder `key`.

    Known keys are validated against their strict type pattern.
    Unknown keys (custom regex capture groups) are checked for shell/PS
    metacharacters.
    """
    if key in _PLACEHOLDER_VALIDATORS:
        pattern = _PLACEHOLDER_VALIDATORS[key]
        if pattern is not None and not pattern.fullmatch(value):
            raise ValueError(
                f"Placeholder '{{{{{key}}}}}' value {value!r} failed type validation "
                f"(expected: {pattern.pattern})"
            )
    else:
        if _DANGEROUS_CHARS_RE.search(value):
            raise ValueError(
                f"Placeholder '{{{{{key}}}}}' value {value!r} contains unsafe characters"
            )


# Remediation scripts can run longer than a quick log-collection command.
# Raise the cap to 2 min; still bounded so a hung script can't hold the pool.
DEFAULT_REMEDIATION_TIMEOUT_S = 120


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

    def _substitute_variables(
        self, template: str, variables: dict, language: str = "bash"
    ) -> str:
        """Replace {{key}} placeholders with validated, OS-escaped values.

        Raises ValueError if any placeholder value fails validation so the
        caller can abort rather than execute a potentially injected command.

        Defense-in-depth escaping is applied after validation:
        - bash   → shlex.quote() handles all POSIX shell metacharacters
        - other  → PS single-quoted string escape: ' → '' so an apostrophe
                   in a value doesn't close the string and allow injection
        """
        if not variables:
            return template

        def replacer(match: re.Match) -> str:
            key = match.group(1).strip()
            raw = variables.get(key)
            if raw is None:
                return match.group(0)   # keep original placeholder

            value = str(raw)
            _validate_placeholder_value(key, value)

            if language == "bash":
                return shlex.quote(value)
            else:
                # PowerShell: escape ' → '' (literal single-quote inside
                # single-quoted PS strings).
                return value.replace("'", "''")

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

        # 3. Variable Substitution (validated + OS-escaped)
        command = script_doc["content"]
        language = script_doc.get("language", "bash")
        try:
            command = self._substitute_variables(command, variables or {}, language)
        except ValueError as exc:
            print(f"🚫 Remediation aborted — unsafe placeholder value: {exc}")
            await db["incidents"].update_one(
                {"_id": ObjectId(incident_id)},
                {"$set": {
                    "automation_failure_reason": f"unsafe_placeholder: {exc}",
                    "status": "open",
                    "verification_until": None,
                }},
            )
            event_bus.emit("incidents", "incident.updated", {
                "incident_id": incident_id,
                "server_id": server_id,
                "reason": "unsafe_placeholder",
            })
            event_bus.emit(f"servers.{server_id}.incidents", "incident.updated", {  # deprecated: remove when RBAC lands
                "incident_id": incident_id,
                "server_id": server_id,
                "reason": "unsafe_placeholder",
            })
            return False

        print(f"📝 Resolved Command: {command}")

        # 4. Execute (timeout enforced inside executor — kills remote process)
        result = await executor.run_command(command, timeout_s=DEFAULT_REMEDIATION_TIMEOUT_S)

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
        event_bus.emit(f"servers.{server_id}.automation", "remediation.executed", {  # deprecated: remove when RBAC lands
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