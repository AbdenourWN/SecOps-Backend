import json
import asyncio
from datetime import datetime, timezone
from typing import List
from app.core.database import get_database
from app.modules.logs.schemas import LogEntryInDB, map_priority_to_level
from app.core.executors import get_server_executor
from app.core.security import decrypt_password
from bson import ObjectId

class LogService:

    async def collect_logs_from_server(self, server_id: str):
        db = get_database()
        
        # 1. Fetch Server & Creds
        try:
            s_oid = ObjectId(server_id)
        except:
            return {"status": "failed", "error": "Invalid ID"}
            
        server = await db["servers"].find_one({"_id": s_oid})
        if not server: return {"status": "failed", "error": "Server not found"}
        
        cred = await db["credentials"].find_one({"_id": ObjectId(server["credential_id"])})
        plain_secret = decrypt_password(cred["encrypted_secret"])

        # 2. Get Executor
        executor = get_server_executor(server, plain_secret)
        executor.credential['username'] = cred['username']

        # 3. ROUTING: Check OS (Future-Proofing)
        if server.get("os_type") == "windows":
            return {"status": "skipped", "message": "Windows log collection coming in v2"}
        
        # 4. RUN LINUX COLLECTION
        return await self._collect_linux_logs(server, executor, db)

    async def _collect_linux_logs(self, server, executor, db):
        """
        Uses journalctl to get structured JSON logs.
        """
        # Command Breakdown:
        # journalctl 
        # --output=json : Get JSON objects
        # --no-pager    : Don't wait for user input
        # -p 4          : Priority 4 (Warning) and higher (Error, Crit). Ignore Info(6).
        # --since "5 minutes ago" : Overlap window to ensure we don't miss anything.
        cmd = 'journalctl --output=json --no-pager -p 4 --since "5 minutes ago"'
        
        result = await executor.run_command(cmd)
        
        if result["status"] == "failed":
            # Fallback: Server might not have journalctl (e.g. Alpine Linux or very old OS)
            return {"status": "error", "error": "Could not fetch logs (journalctl failed)"}

        # 5. Parse Output
        # journalctl outputs ONE JSON object PER LINE. It is not a single JSON array.
        lines = result["output"].split('\n')
        new_logs = []
        count = 0

        for line in lines:
            if not line.strip(): continue
            
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue # Skip broken lines

            # Extract fields safely
            # __REALTIME_TIMESTAMP is in microseconds string (e.g., '1609459200000000')
            ts_micro = int(entry.get("__REALTIME_TIMESTAMP", 0))
            timestamp = datetime.fromtimestamp(ts_micro / 1_000_000, tz=timezone.utc)
            
            message = entry.get("MESSAGE", "")
            service = entry.get("SYSLOG_IDENTIFIER", "system")
            priority = entry.get("PRIORITY", "6") # Default to Info
            
            # Create Model
            log_item = LogEntryInDB(
                server_id=str(server["_id"]),
                timestamp=timestamp,
                message=message,
                service=service,
                level=map_priority_to_level(str(priority)),
                raw_metadata=entry # Store the rest just in case
            )

            # 6. DEDUPLICATION (Crucial step)
            # We check if this specific log already exists.
            # In production, we optimize this by querying "latest timestamp" once.
            # For now, this is safe and accurate.
            exists = await db["logs"].find_one({
                "server_id": str(server["_id"]),
                "timestamp": timestamp,
                "message": message
            })
            
            if not exists:
                new_logs.append(log_item.model_dump())
                count += 1

        # 7. Bulk Insert
        if new_logs:
            await db["logs"].insert_many(new_logs)
            
        return {"status": "success", "new_logs_count": count}

    async def get_logs(self, server_id: str, limit: int = 100):
        db = get_database()
        # Sort by timestamp DESC (newest first)
        cursor = db["logs"].find({"server_id": server_id}).sort("timestamp", -1).limit(limit)
        logs = await cursor.to_list(length=limit)
        
        # Convert ObjectId to string for JSON response
        for log in logs:
            log["_id"] = str(log["_id"])
            
        return logs