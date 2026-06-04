from app.core.constants import Collections, WSTopic
import asyncio
import logging
import shlex
import uuid
from app.core.database import get_database
from app.core.executors import DEFAULT_COMMAND_TIMEOUT_S
from app.core.elasticsearch import get_elasticsearch
from app.core.events import event_bus
from app.modules.logs.schemas import LogLevel
from app.modules.logs.parsers import parse_log_line
from bson import ObjectId
from datetime import datetime, timezone
from elasticsearch.helpers import async_bulk
from app.modules.analysis.service import AnalysisService

logger = logging.getLogger(__name__)


def _get_log_index_name():
    return f"secops-logs-{datetime.now(timezone.utc).strftime('%Y.%m')}"


def _q_linux(path: str) -> str:
    """Shell-quote a path for safe embedding in a bash command string."""
    return shlex.quote(path)


def _q_windows(path: str) -> str:
    """Quote a path for safe embedding in a PowerShell double-quoted string.

    PowerShell uses backtick as the escape character inside double-quoted
    strings. We escape backtick first, then double-quote and dollar sign to
    prevent variable expansion. The result is wrapped in double-quotes so
    that single-quotes in the path are treated as literals.
    """
    path = path.replace('`', '``')   # backtick → ``
    path = path.replace('"', '`"')   # double-quote → `"
    path = path.replace('$', '`$')   # dollar sign → `$ (no variable expansion)
    return f'"{path}"'


class FileWatcherService:

    async def create_source(self, source_data):
        db = get_database()
        new_source = source_data.model_dump()
        # Set Defaults
        new_source["last_offset"] = 0
        new_source["last_inode"] = None
        new_source["last_header"] = None
        new_source["error_count"] = 0
        new_source["is_active"] = True
        new_source["created_at"] = datetime.now(timezone.utc)

        result = await db[Collections.LOG_SOURCES].insert_one(new_source)
        _sid = new_source.get("server_id")
        event_bus.emit(WSTopic.LOG_SOURCES, "log_source.created", {
            "source_id": str(result.inserted_id),
            "server_id": _sid,
        })
        if _sid:
            event_bus.emit(f"servers.{_sid}.log_sources", "log_source.created", {  # per-server topic for detail pages (flat topic above is server-filtered at the WS bridge)
                "source_id": str(result.inserted_id),
                "server_id": _sid,
            })
        return str(result.inserted_id)

    async def get_all_sources(self):
        db = get_database()
        return await db[Collections.LOG_SOURCES].find({"is_active": True}).to_list(length=1000)

    async def get_sources_by_server(self, server_id: str):
        """List every log source registered for a given server (active or not)."""
        db = get_database()
        sources = await db[Collections.LOG_SOURCES].find({"server_id": server_id}).to_list(length=200)
        for s in sources:
            s["_id"] = str(s["_id"])
        return sources

    async def get_source(self, source_id: str):
        db = get_database()
        try:
            doc = await db[Collections.LOG_SOURCES].find_one({"_id": ObjectId(source_id)})
        except Exception:
            return None
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def update_source(self, source_id: str, updates: dict) -> bool:
        """
        Patch a log source. If the file_path or parser changes we reset the
        bookmark state so the next poll re-reads from the start of the new file
        instead of jumping to a stale offset.
        """
        db = get_database()
        try:
            oid = ObjectId(source_id)
        except Exception:
            return False

        clean = {k: v for k, v in updates.items() if v is not None}
        if not clean:
            return True

        # Reset bookmark state when the target file changes
        if "file_path" in clean:
            clean["last_offset"] = 0
            clean["last_inode"] = None
            clean["last_header"] = None
            clean["error_count"] = 0

        # Fetch server_id before update for per-server topic emit
        src = await db[Collections.LOG_SOURCES].find_one({"_id": oid}, {"server_id": 1})
        result = await db[Collections.LOG_SOURCES].update_one({"_id": oid}, {"$set": clean})
        if result.matched_count > 0:
            event_bus.emit(WSTopic.LOG_SOURCES, "log_source.updated", {"source_id": str(oid)})
            _sid = src.get("server_id") if src else None
            if _sid:
                event_bus.emit(f"servers.{_sid}.log_sources", "log_source.updated", {  # per-server topic for detail pages (flat topic above is server-filtered at the WS bridge)
                    "source_id": str(oid), "server_id": _sid,
                })
        return result.matched_count > 0

    async def delete_source(self, source_id: str) -> bool:
        db = get_database()
        try:
            oid = ObjectId(source_id)
        except Exception:
            return False
        # Fetch server_id before delete for per-server topic emit
        src = await db[Collections.LOG_SOURCES].find_one({"_id": oid}, {"server_id": 1})
        result = await db[Collections.LOG_SOURCES].delete_one({"_id": oid})
        if result.deleted_count > 0:
            event_bus.emit(WSTopic.LOG_SOURCES, "log_source.deleted", {"source_id": str(oid)})
            _sid = src.get("server_id") if src else None
            if _sid:
                event_bus.emit(f"servers.{_sid}.log_sources", "log_source.deleted", {  # per-server topic for detail pages (flat topic above is server-filtered at the WS bridge)
                    "source_id": str(oid), "server_id": _sid,
                })
        return result.deleted_count > 0

    # =========================================================================
    # 🚦 MAIN DISPATCHER
    # =========================================================================
    async def process_file_source(self, source_doc: dict):
        from app.core.connection_pool import connection_pool

        db = get_database()
        server_id = source_doc["server_id"]

        server = await db[Collections.SERVERS].find_one({"_id": ObjectId(server_id)})
        if not server:
            return

        # Skip offline servers — avoids hanging on dead hosts
        if not server.get("is_online", True):
            return

        async with connection_pool.try_get(str(server["_id"]), timeout=5) as executor:
            if executor is None:
                return  # server busy with terminal; skip this source this tick

            if server.get("os_type") == "windows":
                await self._process_windows_source(executor, source_doc, db, server)
            else:
                await self._process_linux_source(executor, source_doc, db, server)

    # =========================================================================
    # 🐧 LINUX LOGIC (Bash + Stat + Tail)
    # =========================================================================
    async def _process_linux_source(self, executor, source_doc, db, server=None):
        file_path = source_doc["file_path"]
        last_offset = source_doc.get("last_offset", 0)
        last_inode = source_doc.get("last_inode")
        last_header = source_doc.get("last_header")
        error_count = source_doc.get("error_count", 0)
        source_id = source_doc["_id"]

        # 1. Check Metadata (Size, Inode, Fingerprint)
        qp = _q_linux(file_path)
        chk_cmd = (
            f"stat -c '%s %i' {qp}; echo '---SPLIT---'; head -c 50 {qp}"
        )
        chk_result = await executor.run_command(chk_cmd, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)

        if chk_result["status"] == "failed":
            await self._handle_file_error(source_id, error_count, file_path, db)
            return

        # Success - Reset Error Count
        if error_count > 0:
            await db[Collections.LOG_SOURCES].update_one(
                {"_id": source_id}, {"$set": {"error_count": 0}}
            )

        try:
            parts = chk_result["output"].split("---SPLIT---")
            stat_parts = parts[0].strip().split()
            current_size = int(stat_parts[0])
            current_inode = int(stat_parts[1])
            current_header = parts[1].strip() if len(parts) > 1 else ""
        except (ValueError, IndexError):
            return

        # 2. Determine Read State
        read_start, read_len = self._calculate_read_state(
            last_offset,
            last_inode,
            last_header,
            current_size,
            current_inode,
            current_header,
            file_path,
        )

        if read_len <= 0:
            return

        # 3. Read Data
        # Cap at 1MB
        limit = ""
        if read_len > 1024 * 1024:
            limit = " -c 1000000"

        # Tail command logic
        cmd = f"tail -c +{read_start + 1}{limit} {_q_linux(file_path)}"

        read_result = await executor.run_command(cmd, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)
        if read_result["status"] == "success":
            await self._save_logs(read_result["output"], source_doc, db, server)
            await db[Collections.LOG_SOURCES].update_one(
                {"_id": source_id},
                {"$set": {
                    "last_offset": current_size,
                    "last_inode": current_inode,
                    "last_header": current_header,
                }},
            )

    # =========================================================================
    # 🪟 WINDOWS LOGIC (PowerShell .NET)
    # =========================================================================
    async def _process_windows_source(self, executor, source_doc, db, server=None):
        file_path = source_doc["file_path"]
        last_offset = source_doc.get("last_offset", 0)
        last_inode = str(source_doc.get("last_inode", ""))  # String for Windows
        last_header = source_doc.get("last_header")
        error_count = source_doc.get("error_count", 0)
        source_id = source_doc["_id"]

        # 1. Check Metadata
        # We use Get-Item for Size/Time and Get-Content for Header.
        # _q_windows() wraps the path in double-quotes with PS backtick-escaping
        # so single-quotes, dollar signs, and backticks in the path are safe.
        # -LiteralPath prevents PS from treating [ ] * ? as glob wildcards.
        qp = _q_windows(file_path)
        ps_check = f" $f = Get-Item -LiteralPath {qp} -ErrorAction SilentlyContinue; if (!$f) {{ Write-Output 'MISSING' }} else {{ $header = Get-Content -LiteralPath {qp} -TotalCount 1 -Encoding UTF8; if ($header -and $header.Length -gt 50) {{ $header = $header.Substring(0,50) }}; Write-Output ($f.Length.ToString() + '|' + $f.CreationTimeUtc.Ticks.ToString() + '|' + $header) }}"

        chk_result = await executor.run_command(ps_check, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)

        if chk_result["status"] == "failed" or "MISSING" in chk_result.get(
            "output", ""
        ):
            await self._handle_file_error(source_id, error_count, file_path, db)
            return

        if error_count > 0:
            await db[Collections.LOG_SOURCES].update_one(
                {"_id": source_id}, {"$set": {"error_count": 0}}
            )

        try:
            parts = chk_result["output"].strip().split("|")
            current_size = int(parts[0])
            current_inode = str(parts[1])  # Use CreationTime Ticks as Inode Proxy
            current_header = parts[2] if len(parts) > 2 else ""
        except:
            return

        # 2. Determine Read State
        read_start, read_len = self._calculate_read_state(
            last_offset,
            last_inode,
            last_header,
            current_size,
            current_inode,
            current_header,
            file_path,
        )

        if read_len <= 0:
            return

        # 3. Read Data (Using .NET FileStream for precision)
        if read_len > 1024 * 1024:
            read_len = 1024 * 1024  # Cap 1MB

        ps_read = f" $path = {_q_windows(file_path)}; $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite); $null = $stream.Seek({read_start}, [System.IO.SeekOrigin]::Begin); $buffer = New-Object byte[] {read_len}; $bytesRead = $stream.Read($buffer, 0, {read_len}); $stream.Close(); [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)"

        read_result = await executor.run_command(ps_read, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)
        if read_result["status"] == "success":
            await self._save_logs(read_result["output"], source_doc, db, server)

            await db[Collections.LOG_SOURCES].update_one(
                {"_id": source_id},
                {
                    "$set": {
                        "last_offset": current_size,
                        "last_inode": current_inode,
                        "last_header": current_header,
                    }
                },
            )

    # =========================================================================
    # 🧠 SHARED LOGIC HELPERS
    # =========================================================================

    def _calculate_read_state(
        self, last_off, last_ino, last_head, curr_size, curr_ino, curr_head, path
    ):
        """Decides if we Rotate, Reset, or Append"""
        read_start = 0
        read_len = 0
        is_rotated = False

        # Inode Change (File Replaced)
        if last_ino is not None and str(curr_ino) != str(last_ino):
            logger.info("Rotation (inode) for %s", path)
            is_rotated = True

        # Size Drop (Truncation)
        elif curr_size < last_off:
            logger.info("Truncation (size) for %s", path)
            is_rotated = True

        # Header Mismatch (Overwrite)
        elif last_head and curr_head and not str(curr_head).startswith(str(last_head)):
            logger.info("Overwrite (header) for %s", path)
            is_rotated = True

        if is_rotated:
            read_start = 0
            read_len = curr_size
        elif curr_size == last_off:
            return 0, 0
        else:
            read_start = last_off
            read_len = curr_size - last_off

        return read_start, read_len

    async def _handle_file_error(self, source_id, error_count, path, db):
        new_count = error_count + 1
        logger.warning("File check failed (%d/10) for %s", new_count, path)
        updates = {"error_count": new_count}
        if new_count >= 10:
            logger.warning("File path %s seems dead — disabling", path)
            updates["is_active"] = False
        await db[Collections.LOG_SOURCES].update_one({"_id": source_id}, {"$set": updates})

    async def _save_logs(self, raw_data, source_doc, db, server=None):
        if not raw_data:
            return

        server_id = source_doc["server_id"]
        hostname = (server or {}).get("hostname") or server_id
        os_type = (server or {}).get("os_type", "linux")
        parser_type = source_doc.get("parser_type", "raw")
        ingestion_time = datetime.now(timezone.utc)

        lines = raw_data.split("\n")
        new_logs = []
        for line in lines:
            if not line.strip():
                continue
            parsed = parse_log_line(line, parser_type, ingestion_time)
            doc_id = str(uuid.uuid4())
            new_logs.append({
                "_id": doc_id,
                "server_id": server_id,
                "hostname": hostname,
                "timestamp": parsed["timestamp"].isoformat(),
                "message": parsed["message"],
                "service": source_doc["name"],
                "level": parsed["level"].upper(),
                "os_type": os_type,
                "source": "file_watcher",
                "log_source": source_doc.get("name", "file"),
                "ingested_at": ingestion_time.isoformat(),
            })

        if not new_logs:
            return

        # Index to Elasticsearch so logs appear in the frontend viewer
        es = get_elasticsearch()
        if es:
            try:
                actions = [
                    {
                        "_index": _get_log_index_name(),
                        "_id": doc["_id"],
                        "_source": {k: v for k, v in doc.items() if k != "_id"},
                    }
                    for doc in new_logs
                ]
                await async_bulk(es, actions, raise_on_error=False)
            except Exception as e:
                logger.warning("ES bulk index error (file_watcher): %s", e)

        await AnalysisService().analyze_logs(new_logs)
        event_bus.emit(f"servers.{server_id}.logs", "logs.ingested", {
            "server_id": server_id,
            "source_id": str(source_doc.get("_id", "")),
            "count": len(new_logs),
        })
        logger.info("Indexed %d lines from %s -> ES", len(new_logs), source_doc['file_path'])
