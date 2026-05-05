import json
import uuid
from datetime import datetime, timezone
from typing import List
from app.core.database import get_database
from app.core.elasticsearch import get_elasticsearch
from app.modules.logs.schemas import LogEntryInDB, map_priority_to_level
from app.core.executors import get_server_executor, DEFAULT_COMMAND_TIMEOUT_S
from app.core.security import decrypt_password
from app.core.datetime_utils import utc_now
from bson import ObjectId
from app.modules.analysis.service import AnalysisService
from app.modules.logs.schemas import LogLevel
from elasticsearch.helpers import async_bulk


def _get_log_index_name():
    return f"secops-logs-{utc_now().strftime('%Y.%m')}"


class LogService:

    def __init__(self):
        self.analysis_service = AnalysisService()

    # ========================================================================
    # OPT-2: BULK ES INDEXING
    # Instead of 1 HTTP request per log, we send ALL logs in 1 request.
    # ========================================================================

    async def _bulk_index_to_es(self, log_docs: list[dict]) -> bool:
        """
        Indexes multiple log documents into ES in a single HTTP request.
        
        HOW ES BULK API WORKS:
        - Sends all documents in one HTTP body (NDJSON format internally)
        - ES processes them as a batch — much faster than individual requests
        - Each action dict needs _index, _id, and _source
        """
        es = get_elasticsearch()
        if not es or not log_docs:
            return False

        try:
            actions = [
                {
                    "_index": _get_log_index_name(),
                    "_id": doc["_id"],
                    "_source": {k: v for k, v in doc.items() if k != "_id"},
                }
                for doc in log_docs
            ]
            await async_bulk(es, actions, raise_on_error=False)
            return True
        except Exception as e:
            print(f"⚠️ ES bulk index error: {e}")
            return False

    # ========================================================================
    # OPT-3: O(1) DEDUPLICATION
    # Instead of 1 ES query per log line, we query ONCE for the latest
    # timestamp and skip all older logs with a pure Python comparison.
    # ========================================================================

    async def _get_latest_timestamp(self, server_id: str) -> str | None:
        """
        Returns the most recent log timestamp for a server from ES.
        
        WHY THIS IS BETTER:
        - Old approach: 200 logs × 1 ES search each = 200 HTTP requests
        - New approach: 1 ES search for the newest timestamp = 1 HTTP request
        - Then we skip old logs with a simple string comparison (pure Python, zero network)
        """
        es = get_elasticsearch()
        if not es:
            return None

        try:
            result = await es.search(
                index="secops-logs-*",
                body={
                    "query": {"term": {"server_id": server_id}},
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": 1,
                    "_source": ["timestamp"],
                }
            )
            if result["hits"]["hits"]:
                return result["hits"]["hits"][0]["_source"]["timestamp"]
            return None
        except Exception:
            return None

    async def collect_logs_with(self, executor, server: dict):
        """
        Collect logs using a pre-resolved pooled executor.
        Called by the combined scheduler job (no credential lookup needed).
        """
        if server.get("os_type") == "windows":
            return await self._collect_windows_logs(server, executor)
        return await self._collect_linux_logs(server, executor)

    async def collect_logs_from_server(self, server_id: str):
        """Backwards-compatible wrapper — resolves executor from DB then delegates to collect_logs_with."""
        db = get_database()
        try:
            s_oid = ObjectId(server_id)
        except Exception:
            return {"status": "failed", "error": "Invalid ID"}
        server = await db["servers"].find_one({"_id": s_oid})
        if not server:
            return {"status": "failed", "error": "Server not found"}
        cred = await db["credentials"].find_one({"_id": ObjectId(server["credential_id"])})
        plain_secret = decrypt_password(cred["encrypted_secret"])
        executor = get_server_executor(server, plain_secret)
        executor.credential["username"] = cred["username"]
        return await self.collect_logs_with(executor, server)

    async def _collect_linux_logs(self, server, executor):
        """
        Uses journalctl to get structured JSON logs.
        Saves to Elasticsearch using bulk indexing.
        """
        cmd = 'journalctl --output=json --no-pager -p 4 --since "5 minutes ago"'
        
        result = await executor.run_command(cmd, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)
        
        if result["status"] == "failed":
            return {"status": "error", "error": "Could not fetch logs (journalctl failed)"}

        # OPT-3: Get the latest timestamp ONCE (1 query instead of N)
        server_id = str(server["_id"])
        latest_ts = await self._get_latest_timestamp(server_id)

        # Parse Output (journalctl outputs ONE JSON object PER LINE)
        lines = result["output"].split('\n')
        new_logs = []

        for line in lines:
            if not line.strip():
                continue
            
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract fields
            ts_micro = int(entry.get("__REALTIME_TIMESTAMP", 0))
            timestamp = datetime.fromtimestamp(ts_micro / 1_000_000, tz=timezone.utc)
            ts_iso = timestamp.isoformat()
            
            message = entry.get("MESSAGE") or ""
            service = entry.get("SYSLOG_IDENTIFIER") or "system"
            priority = entry.get("PRIORITY") or "6"
            
            # OPT-3: Skip logs older than what we already have (pure Python, no network)
            if latest_ts and ts_iso <= latest_ts:
                continue

            # Generate a unique ID for this log
            doc_id = str(uuid.uuid4())

            log_doc = {
                "_id": doc_id,
                "server_id": server_id,
                "hostname": server.get("hostname", server.get("ip_address")),
                "timestamp": ts_iso,
                "message": message,
                "service": service,
                "level": map_priority_to_level(str(priority)).value,
                "os_type": "linux",
                "source": "journalctl",
                "log_source": "system",
                "ingested_at": utc_now().isoformat(),
            }

            new_logs.append(log_doc)

        # OPT-2: Bulk index ALL new logs in one HTTP request
        if new_logs:
            await self._bulk_index_to_es(new_logs)

        # Trigger Analysis Engine with the new logs (in-memory)
        if new_logs:
            await self.analysis_service.analyze_logs(new_logs)
            
        return {"status": "success", "new_logs_count": len(new_logs)}

    async def _collect_windows_logs(self, server, executor):
        """
        Fetches Windows Event Logs (System & Security) as JSON.
        Saves to Elasticsearch using bulk indexing.
        """
        # ForEach-Object builds a plain PSCustomObject so ConvertTo-Json depth
        # is irrelevant and TimeCreated is ISO-8601.  The $m fallback pulls the
        # raw substitution strings when the source has no registered message DLL
        # (the common case for custom Write-EventLog sources).
        ps_script = (
            "Get-WinEvent -FilterHashTable @{LogName='System','Security','Application';"
            "Level=1,2,3;StartTime=(Get-Date).AddMinutes(-5)} -EA SilentlyContinue|"
            "%{$m=$_.Message;"
            "if(-not $m){$m=($_.Properties.Value|?{$_ -is [string]})-join' '};"
            "if(-not $m){$m=\"EventId=$($_.Id)\"};"
            "[PSCustomObject]@{TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');"
            "Id=$_.Id;LevelDisplayName=$_.LevelDisplayName;"
            "Message=$m;ProviderName=$_.ProviderName}}|ConvertTo-Json -Compress"
        )
        
        result = await executor.run_command(ps_script, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)
        
        output = result.get("output", "")
        if not output: 
            return {"status": "success", "new_logs_count": 0}
            
        try:
            if not output.strip().startswith("["):
                output = f"[{output}]"
            entries = json.loads(output)
        except json.JSONDecodeError:
            return {"status": "error", "error": "JSON Parse Error on Windows Logs"}

        # OPT-3: Get the latest timestamp ONCE
        server_id = str(server["_id"])
        latest_ts = await self._get_latest_timestamp(server_id)

        new_logs = []
        for entry in entries:
            # Parse Level
            lvl_str = str(entry.get("LevelDisplayName", "")).lower()
            level = LogLevel.UNKNOWN
            if "error" in lvl_str or "critical" in lvl_str:
                level = LogLevel.ERROR
            elif "warning" in lvl_str:
                level = LogLevel.WARNING

            message = entry.get("Message") or ""

            tc = entry.get("TimeCreated") or ""
            try:
                timestamp = datetime.fromisoformat(tc.replace("Z", "+00:00")).astimezone(timezone.utc) if tc else utc_now()
            except (ValueError, AttributeError):
                timestamp = utc_now()
            ts_iso = timestamp.isoformat()

            # OPT-3: Skip if we already have this timestamp
            if latest_ts and ts_iso <= latest_ts:
                continue

            doc_id = str(uuid.uuid4())

            log_doc = {
                "_id": doc_id,
                "server_id": server_id,
                "hostname": server.get("hostname", server.get("ip_address")),
                "timestamp": ts_iso,
                "message": message,
                "service": entry.get("ProviderName", "Windows"),
                "level": level.value,
                "os_type": "windows",
                "source": "winevent",
                "log_source": "system",
                "ingested_at": utc_now().isoformat(),
            }

            new_logs.append(log_doc)

        # OPT-2: Bulk index ALL at once
        if new_logs:
            await self._bulk_index_to_es(new_logs)

        # Trigger analysis
        if new_logs:
            await self.analysis_service.analyze_logs(new_logs)

        return {"status": "success", "new_logs_count": len(new_logs)}

    async def get_logs(self, server_id: str, limit: int = 100):
        """
        Fetches logs from Elasticsearch for a specific server.
        """
        es = get_elasticsearch()
        if not es:
            return []

        try:
            result = await es.search(
                index="secops-logs-*",
                body={
                    "query": {
                        "term": {"server_id": server_id}
                    },
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": limit,
                }
            )

            logs = []
            for hit in result["hits"]["hits"]:
                doc = hit["_source"]
                doc["_id"] = hit["_id"]
                logs.append(doc)

            return logs
        except Exception as e:
            print(f"⚠️ ES search error: {e}")
            return []