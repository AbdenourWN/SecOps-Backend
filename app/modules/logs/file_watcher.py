import asyncio
from app.core.database import get_database
from app.modules.logs.schemas import LogEntryInDB, LogLevel
from app.core.executors import get_server_executor
from app.core.security import decrypt_password
from bson import ObjectId
from datetime import datetime, timezone
from app.modules.analysis.service import AnalysisService


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

        result = await db["log_sources"].insert_one(new_source)
        return str(result.inserted_id)

    async def get_all_sources(self):
        db = get_database()
        return await db["log_sources"].find({"is_active": True}).to_list(length=1000)

    async def get_sources_by_server(self, server_id: str):
        """List every log source registered for a given server (active or not)."""
        db = get_database()
        sources = await db["log_sources"].find({"server_id": server_id}).to_list(length=200)
        for s in sources:
            s["_id"] = str(s["_id"])
        return sources

    async def get_source(self, source_id: str):
        db = get_database()
        try:
            doc = await db["log_sources"].find_one({"_id": ObjectId(source_id)})
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

        result = await db["log_sources"].update_one({"_id": oid}, {"$set": clean})
        return result.matched_count > 0

    async def delete_source(self, source_id: str) -> bool:
        db = get_database()
        try:
            oid = ObjectId(source_id)
        except Exception:
            return False
        result = await db["log_sources"].delete_one({"_id": oid})
        return result.deleted_count > 0

    # =========================================================================
    # 🚦 MAIN DISPATCHER
    # =========================================================================
    async def process_file_source(self, source_doc: dict):
        db = get_database()
        server_id = source_doc["server_id"]

        # 1. Fetch Server & Executor (Shared Logic)
        server = await db["servers"].find_one({"_id": ObjectId(server_id)})
        if not server:
            return

        cred = await db["credentials"].find_one(
            {"_id": ObjectId(server["credential_id"])}
        )
        plain_secret = decrypt_password(cred["encrypted_secret"])

        executor = get_server_executor(server, plain_secret)
        executor.credential["username"] = cred["username"]

        # 2. Dispatch based on OS
        if server.get("os_type") == "windows":
            await self._process_windows_source(executor, source_doc, db)
        else:
            await self._process_linux_source(executor, source_doc, db)

    # =========================================================================
    # 🐧 LINUX LOGIC (Bash + Stat + Tail)
    # =========================================================================
    async def _process_linux_source(self, executor, source_doc, db):
        file_path = source_doc["file_path"]
        last_offset = source_doc.get("last_offset", 0)
        last_inode = source_doc.get("last_inode")
        last_header = source_doc.get("last_header")
        error_count = source_doc.get("error_count", 0)
        source_id = source_doc["_id"]

        # 1. Check Metadata (Size, Inode, Fingerprint)
        chk_cmd = (
            f"stat -c '%s %i' {file_path}; echo '---SPLIT---'; head -c 50 {file_path}"
        )
        chk_result = await executor.run_command(chk_cmd)

        if chk_result["status"] == "failed":
            await self._handle_file_error(source_id, error_count, file_path, db)
            return

        # Success - Reset Error Count
        if error_count > 0:
            await db["log_sources"].update_one(
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
        cmd = f"tail -c +{read_start + 1}{limit} {file_path}"

        read_result = await executor.run_command(cmd)
        if read_result["status"] == "success":
            await self._save_logs(read_result["output"], source_doc, db)

            # Update State
            await db["log_sources"].update_one(
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
    # 🪟 WINDOWS LOGIC (PowerShell .NET)
    # =========================================================================
    async def _process_windows_source(self, executor, source_doc, db):
        file_path = source_doc["file_path"]
        last_offset = source_doc.get("last_offset", 0)
        last_inode = str(source_doc.get("last_inode", ""))  # String for Windows
        last_header = source_doc.get("last_header")
        error_count = source_doc.get("error_count", 0)
        source_id = source_doc["_id"]

        # 1. Check Metadata
        # We use Get-Item for Size/Time and Get-Content for Header
        ps_check = f" $f = Get-Item '{file_path}' -ErrorAction SilentlyContinue; if (!$f) {{ Write-Output 'MISSING' }} else {{ $header = Get-Content '{file_path}' -TotalCount 1 -Encoding UTF8; if ($header -and $header.Length -gt 50) {{ $header = $header.Substring(0,50) }}; Write-Output ($f.Length.ToString() + '|' + $f.CreationTimeUtc.Ticks.ToString() + '|' + $header) }}"

        chk_result = await executor.run_command(ps_check)

        if chk_result["status"] == "failed" or "MISSING" in chk_result.get(
            "output", ""
        ):
            await self._handle_file_error(source_id, error_count, file_path, db)
            return

        if error_count > 0:
            await db["log_sources"].update_one(
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

        ps_read = f" $path = '{file_path}'; $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite); $null = $stream.Seek({read_start}, [System.IO.SeekOrigin]::Begin); $buffer = New-Object byte[] {read_len}; $bytesRead = $stream.Read($buffer, 0, {read_len}); $stream.Close(); [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)"

        read_result = await executor.run_command(ps_read)
        print(f"🐛 WINDOWS READ RESULT: {read_result}")
        if read_result["status"] == "success":
            await self._save_logs(read_result["output"], source_doc, db)

            await db["log_sources"].update_one(
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
            print(f"🔄 Rotation (Inode) for {path}")
            is_rotated = True

        # Size Drop (Truncation)
        elif curr_size < last_off:
            print(f"📉 Truncation (Size) for {path}")
            is_rotated = True

        # Header Mismatch (Overwrite)
        elif last_head and curr_head and not str(curr_head).startswith(str(last_head)):
            print(f"📝 Overwrite (Header) for {path}")
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
        print(f"⚠️ File check failed ({new_count}/10) for {path}")
        updates = {"error_count": new_count}
        if new_count >= 10:
            print(f"💀 file_path {path} seems dead. Disabling.")
            updates["is_active"] = False
        await db["log_sources"].update_one({"_id": source_id}, {"$set": updates})

    async def _save_logs(self, raw_data, source_doc, db):
        if not raw_data:
            return

        lines = raw_data.split("\n")
        new_logs = []
        for line in lines:
            if not line.strip():
                continue
            log_entry = LogEntryInDB(
                server_id=source_doc["server_id"],
                timestamp=datetime.now(timezone.utc),
                message=line.strip(),
                service=source_doc["name"],
                level=LogLevel.INFO,
            )
            new_logs.append(log_entry.model_dump())

        if new_logs:
            res = await db["logs"].insert_many(new_logs)
            analysis_service = AnalysisService()
            for i, log in enumerate(new_logs):
                log["_id"] = res.inserted_ids[i]
            await analysis_service.analyze_logs(new_logs)
            print(f"📥 Collected {len(new_logs)} lines from {source_doc['file_path']}")
