import asyncio
import uuid
from typing import AsyncIterator, Optional, Union

from app.core.database import get_database
from app.modules.servers.schemas import ServerCreate, ServerInDB, CredentialInDB, ServerUpdate, ServerDelete, ServerStatus
from app.core.security import encrypt_password, decrypt_password
from bson import ObjectId
from datetime import datetime, timezone
from app.core.executors import get_server_executor, Chunk, ChunkDone
# get_server_executor kept for health-check path (direct TCP, no pool)
from app.core.rate_limit import check_rate_limit
from app.modules.servers.guardrails import check_command
from app.modules.servers.audit import write_audit
from app.core.events import event_bus
from app.core.connection_pool import connection_pool


DEFAULT_COMMAND_TIMEOUT_S = 60
MAX_COMMAND_TIMEOUT_S = 300



class ServerService:
    async def _verify_ownership(self, db, server_id: ObjectId, input_secret: str) -> dict:
        """
        Private helper. Checks if the input_secret matches the stored credential.
        Returns the credential document if valid, raises error if not.
        """
        # 1. Find Server
        server = await db["servers"].find_one({"_id": server_id})
        if not server:
            return {"valid": False, "error": "Server not found"}

        # 2. Find Linked Credential
        cred_id = server["credential_id"] # It's an ObjectId now
        credential = await db["credentials"].find_one({"_id": ObjectId(cred_id)})
        
        if not credential:
            return {"valid": False, "error": "Critical Data Corruption: Credential missing"}

        # 3. Decrypt Stored Secret
        try:
            stored_secret = decrypt_password(credential["encrypted_secret"])
        except:
             return {"valid": False, "error": "Decryption failed"}

        # 4. Compare
        # We strip() whitespace just in case of copy-paste errors
        if input_secret.strip() != stored_secret.strip():
            return {"valid": False, "error": "Authentication Failed: Wrong current password"}

        return {"valid": True, "credential_id": cred_id, "server_data": server}
    
    async def update_all_server_statuses(self):
        from app.core.config import settings

        db = get_database()
        servers = await db["servers"].find().to_list(length=10000)
        print(f"🕵️  Starting Health Check Cycle...")

        sem = asyncio.Semaphore(settings.MAX_CONCURRENT_SERVERS)

        async def check_one(server):
            server_id = str(server["_id"])
            previous_status = server.get("status")
            async with sem:
                # Health check uses a direct TCP ping — no pooled session needed,
                # no per-server lock needed (read-only probe, no auth collision).
                executor = get_server_executor(server, plain_password="")
                is_online = await executor.check_health()
                new_status = ServerStatus.ONLINE if is_online else ServerStatus.OFFLINE

                await db["servers"].update_one(
                    {"_id": server["_id"]},
                    {"$set": {
                        "status": new_status,
                        "is_online": is_online,
                        "last_health_check": datetime.now(timezone.utc),
                    }},
                )

                if previous_status != new_status:
                    event_bus.emit("servers.status", "server.status_changed", {
                        "server_id": server_id,
                        "status": new_status,
                        "previous_status": previous_status,
                        "hostname": server.get("hostname"),
                    })
                    event_bus.emit("dashboard.summary", "server.status_changed", {
                        "server_id": server_id,
                        "status": new_status,
                    })

        tasks = [check_one(server) for server in servers]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f"✅ Health Check Complete. Scanned {len(servers)} servers.")
    """ 
    🚀
    CRUD Operations 
    
    """

    async def create_server(self, server_data: ServerCreate):
        db = get_database()
        
        # 1. Check if Server IP exists
        if await db["servers"].find_one({"ip_address": server_data.ip_address}):
            return {"status": "failed", "error": "Server with this IP already exists"}

        # --- STEP A: Handle Credential ---
        
        # Encrypt the secret from the nested input
        encrypted_secret = encrypt_password(server_data.credential.secret)
        encrypted_passphrase = None
        if server_data.credential.passphrase:
            encrypted_passphrase = encrypt_password(server_data.credential.passphrase)

        # --- LOGIC: Handle Default Port ---
        final_port = server_data.port
        if final_port is None:
            # Auto-assign based on OS
            if server_data.os_type == "windows":
                final_port = 5985
            else:
                final_port = 22

        # Prepare Credential Object
        cred_in_db = CredentialInDB(
            username=server_data.credential.username,
            type=server_data.credential.type,
            encrypted_secret=encrypted_secret,
            encrypted_passphrase=encrypted_passphrase
        )

        # Save Credential to "credentials" collection
        cred_result = await db["credentials"].insert_one(cred_in_db.model_dump())
        new_cred_id = cred_result.inserted_id 
        
        # --- STEP B: Handle Server ---

        # Prepare Server Object (Linking the ID)
        server_in_db = ServerInDB(
            hostname=server_data.hostname,
            ip_address=server_data.ip_address,
            os_type=server_data.os_type,
            port=final_port,
            credential_id=str(new_cred_id)
        )

        # Save Server to "servers" collection
        server_result = await db["servers"].insert_one(server_in_db.model_dump())

        event_bus.emit("servers", "server.created", {
            "server_id": str(server_result.inserted_id),
            "hostname": server_data.hostname,
        })
        event_bus.emit("dashboard.summary", "server.created", {
            "server_id": str(server_result.inserted_id),
        })

        return {
            "status": "success",
            "server_id": str(server_result.inserted_id),
            "credential_id": str(new_cred_id)
        }
    
    async def get_all_servers(self, status=None, os_type=None, search=None, page: int = 1, page_size: int = 9):
        db = get_database()
        query = {}
        if status is not None:
            query["status"] = status
        if os_type is not None:
            query["os_type"] = os_type
        if search:
            import re
            pattern = re.compile(re.escape(search), re.IGNORECASE)
            query["$or"] = [{"hostname": pattern}, {"ip_address": pattern}]
        total = await db["servers"].count_documents(query)
        skip = (page - 1) * page_size
        servers = await db["servers"].find(query).skip(skip).limit(page_size).to_list(page_size)
        return {"total": total, "page": page, "page_size": page_size, "results": servers}

    async def get_server(self, server_id: str):
        db = get_database()
        
        try:
            oid = ObjectId(server_id)
        except:
            return None
            
        server = await db["servers"].find_one({"_id": oid})
        return server


    # --- UPDATE Logic ---
    async def update_server(self, server_id: str, update_data: ServerUpdate):
        db = get_database()
        try:
            oid = ObjectId(server_id)
        except:
            return {"status": "failed", "error": "Invalid Server ID"}

        # 1. SECURITY CHALLENGE: Verify the current password first
        verification = await self._verify_ownership(db, oid, update_data.current_secret)
        if not verification["valid"]:
            return {"status": "failed", "error": verification["error"]}
        
        # 2. Prepare Data to Update
        server_updates = {}
        if update_data.hostname: server_updates["hostname"] = update_data.hostname
        if update_data.ip_address: 
            # Check uniqueness if IP is changing
            dup = await db["servers"].find_one({"ip_address": update_data.ip_address, "_id": {"$ne": oid}})
            if dup: return {"status": "failed", "error": "IP already taken"}
            server_updates["ip_address"] = update_data.ip_address
        if update_data.os_type: server_updates["os_type"] = update_data.os_type
        if update_data.port: server_updates["port"] = update_data.port 
        
        # 3. Handle Credential Updates (If user wants to set a NEW password)
        if update_data.credential:
            cred_updates = {}
            if update_data.credential.username: 
                cred_updates["username"] = update_data.credential.username
            if update_data.credential.type: 
                cred_updates["type"] = update_data.credential.type
            if update_data.credential.secret: 
                cred_updates["encrypted_secret"] = encrypt_password(update_data.credential.secret)
            if update_data.credential.passphrase:
                cred_updates["encrypted_passphrase"] = encrypt_password(update_data.credential.passphrase)
            
            # Update the Credential Collection
            if cred_updates:
                cred_updates["updated_at"] = datetime.now(timezone.utc)
                await db["credentials"].update_one(
                    {"_id": ObjectId(verification["credential_id"])}, 
                    {"$set": cred_updates}
                )

        # 4. Update the Server Collection
        if server_updates:
            server_updates["updated_at"] = datetime.now(timezone.utc)
            await db["servers"].update_one({"_id": oid}, {"$set": server_updates})

        # Evict from connection pool so the next access picks up fresh credentials/config
        connection_pool.evict(str(oid))

        event_bus.emit("servers", "server.updated", {"server_id": str(oid)})

        return {"status": "success", "message": "Server and credentials updated"}

    # --- DELETE Logic ---
    async def delete_server(self, server_id: str, delete_data: ServerDelete):
        db = get_database()
        try:
            oid = ObjectId(server_id)
        except:
            return {"status": "failed", "error": "Invalid Server ID"}

        # 1. SECURITY CHALLENGE
        verification = await self._verify_ownership(db, oid, delete_data.current_secret)
        if not verification["valid"]:
             return {"status": "failed", "error": verification["error"]}
        
        cred_id = ObjectId(verification["credential_id"])

        # 2. DELETE EVERYTHING (Cascade)
        await db["servers"].delete_one({"_id": oid})
        await db["credentials"].delete_one({"_id": cred_id})
        # Evict from connection pool — releases the cached session immediately
        connection_pool.evict(str(oid))

        event_bus.emit("servers", "server.deleted", {"server_id": str(oid)})
        event_bus.emit("dashboard.summary", "server.deleted", {"server_id": str(oid)})

        return {"status": "success", "message": "Server and associated credentials deleted"}
    


    async def execute_command_by_id(
        self,
        server_id: str,
        command: str,
        *,
        confirmed: bool = False,
        timeout_s: int | None = None,
        principal_id: str | None = None,
        source_ip: str | None = None,
    ):
        """
        Guardrail pipeline (defense in depth):
          rate-limit -> block-list -> confirm-list -> exec with timeout.
        Every outcome writes a row to command_audit.
        """
        db = get_database()
        started_at = datetime.now(timezone.utc)
        principal = principal_id or source_ip or "anonymous"

        # --- Server lookup ---
        try:
            s_oid = ObjectId(server_id)
        except Exception:
            return {"status": "failed", "error": "Invalid Server ID"}

        server = await db["servers"].find_one({"_id": s_oid})
        if not server:
            return {"status": "failed", "error": "Server not found"}

        os_type = server.get("os_type", "linux")

        # --- 1. Rate limit ---
        rl = await check_rate_limit(principal, server_id)
        if not rl.allowed:
            await write_audit(
                server_id=server_id, command=command, status="rate_limited",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=f"rate limit exceeded (retry in {rl.retry_after_s}s)",
            )
            return {
                "status": "rate_limited",
                "retry_after_seconds": rl.retry_after_s,
                "error": "Rate limit exceeded.",
            }

        # --- 2. Guardrail check (block / confirm / allow) ---
        check = check_command(command, os_type)
        if not check.allowed:
            await write_audit(
                server_id=server_id, command=command, status="blocked",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=check.reason,
            )
            return {
                "status": "blocked",
                "blocked_reason": check.reason,
                "error": check.reason,
            }

        if check.requires_confirmation and not confirmed:
            await write_audit(
                server_id=server_id, command=command, status="requires_confirmation",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=False,
                blocked_reason=check.reason,
            )
            return {
                "status": "requires_confirmation",
                "blocked_reason": check.reason,
                "error": check.reason,
            }

        # --- 3. Acquire pooled executor and run ---
        effective_timeout = DEFAULT_COMMAND_TIMEOUT_S if timeout_s is None else \
            max(1, min(MAX_COMMAND_TIMEOUT_S, int(timeout_s)))

        try:
            async with connection_pool.get(server_id) as executor:
                try:
                    result = await asyncio.wait_for(
                        executor.run_command(command), timeout=effective_timeout
                    )
                except asyncio.TimeoutError:
                    await write_audit(
                        server_id=server_id, command=command, status="timeout",
                        started_at=started_at, principal_id=principal_id,
                        source_ip=source_ip, confirmed=confirmed,
                        stderr=f"[timed out after {effective_timeout}s]",
                    )
                    return {
                        "status": "timeout",
                        "output": "",
                        "error": f"Command exceeded {effective_timeout}s timeout.",
                        "timeout_s": effective_timeout,
                    }
        except Exception as e:
            await write_audit(
                server_id=server_id, command=command, status="error",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed, stderr=str(e),
            )
            return {"status": "failed", "error": str(e)}

        # --- 4. Audit the run ---
        run_status = result.get("status", "error")
        audit_status = "ok" if run_status == "success" else "error"
        await write_audit(
            server_id=server_id, command=command, status=audit_status,
            started_at=started_at, principal_id=principal_id,
            source_ip=source_ip, confirmed=confirmed,
            stdout=result.get("output"),
            stderr=result.get("error"),
        )
        return result

    # ------------------------------------------------------------------
    # Streaming terminal (P7.6)
    # ------------------------------------------------------------------

    async def stream_command(
        self,
        server_id: str,
        command: str,
        abort_event: asyncio.Event,
        *,
        confirmed: bool = False,
        timeout_s: int | None = None,
        principal_id: str | None = None,
        source_ip: str | None = None,
        stdin_queue: Optional[asyncio.Queue] = None,
    ) -> AsyncIterator[dict]:
        """
        Guardrail-checked streaming command.  Yields dicts matching the WS
        protocol:  started | chunk | done | error.
        Always writes an audit row (including on abort/disconnect).
        """
        started_at = datetime.now(timezone.utc)
        principal = principal_id or source_ip or "anonymous"
        command_id = str(uuid.uuid4())

        db = get_database()
        try:
            s_oid = ObjectId(server_id)
        except Exception:
            yield {"type": "error", "command_id": None, "code": "invalid_command",
                   "message": "Invalid server ID"}
            return

        server = await db["servers"].find_one({"_id": s_oid})
        if not server:
            yield {"type": "error", "command_id": None, "code": "invalid_command",
                   "message": "Server not found"}
            return

        os_type = server.get("os_type", "linux")

        # --- Rate limit ---
        rl = await check_rate_limit(principal, server_id)
        if not rl.allowed:
            await write_audit(
                server_id=server_id, command=command, status="rate_limited",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=f"rate limit exceeded (retry in {rl.retry_after_s}s)",
                transport="ws",
            )
            yield {
                "type": "error", "command_id": None, "code": "rate_limited",
                "message": "Rate limit exceeded.",
                "retry_after_s": rl.retry_after_s,
            }
            return

        # --- Guardrail check ---
        check = check_command(command, os_type)
        if not check.allowed:
            await write_audit(
                server_id=server_id, command=command, status="blocked",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=check.reason, transport="ws",
            )
            yield {"type": "error", "command_id": None, "code": "blocked",
                   "message": check.reason}
            return

        if check.requires_confirmation and not confirmed:
            await write_audit(
                server_id=server_id, command=command, status="requires_confirmation",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=False,
                blocked_reason=check.reason, transport="ws",
            )
            yield {"type": "error", "command_id": None,
                   "code": "requires_confirmation", "message": check.reason}
            return

        effective_timeout = (
            DEFAULT_COMMAND_TIMEOUT_S if timeout_s is None
            else max(1, min(MAX_COMMAND_TIMEOUT_S, int(timeout_s)))
        )

        # Acquire the pooled executor — holds the per-server lock for the full
        # streaming duration, serialising terminal and scheduler on this server.
        try:
            _pool_ctx = connection_pool.get(server_id)
            executor = await _pool_ctx.__aenter__()
        except Exception as exc:
            yield {"type": "error", "command_id": None, "code": "internal",
                   "message": str(exc)}
            return

        yield {
            "type": "started",
            "command_id": command_id,
            "command": command,
            "started_at": started_at.isoformat(),
        }

        # Rolling 4 KB preview buffers for audit
        stdout_preview_buf: list[str] = []
        stderr_preview_buf: list[str] = []
        PREVIEW_MAX = 4096
        stdout_total = 0
        stderr_total = 0
        chunk_count = 0
        seq = 0
        final_done: ChunkDone | None = None

        try:
            async for item in executor.stream_command(command, abort_event, effective_timeout, stdin_queue):
                if isinstance(item, Chunk):
                    chunk_count += 1
                    seq_val = seq
                    seq += 1
                    yield {
                        "type": "chunk",
                        "command_id": command_id,
                        "stream": item.stream,
                        "data": item.data,
                        "seq": seq_val,
                    }
                    raw = item.data.encode("utf-8", errors="replace")
                    if item.stream == "stdout":
                        stdout_total += len(raw)
                        if stdout_total <= PREVIEW_MAX:
                            stdout_preview_buf.append(item.data)
                    else:
                        stderr_total += len(raw)
                        if stderr_total <= PREVIEW_MAX:
                            stderr_preview_buf.append(item.data)

                elif isinstance(item, ChunkDone):
                    final_done = item
                    finished_at = datetime.now(timezone.utc)
                    duration_ms = int(
                        (finished_at - started_at).total_seconds() * 1000
                    )
                    yield {
                        "type": "done",
                        "command_id": command_id,
                        "exit_code": item.exit_code,
                        "duration_ms": duration_ms,
                        "status": item.status,
                    }
        finally:
            finished_at = datetime.now(timezone.utc)
            fd = final_done
            aborted = fd is not None and fd.status == "aborted"
            timed_out = fd is not None and fd.status == "timeout"
            if aborted:
                abort_reason = "user" if abort_event.is_set() else "client_disconnect"
            elif timed_out:
                abort_reason = "timeout"
            else:
                abort_reason = None

            audit_status: str
            if fd is None:
                audit_status = "error"
            elif fd.status == "success":
                audit_status = "ok"
            elif fd.status in ("timeout",):
                audit_status = "timeout"
            else:
                audit_status = "error"

            await write_audit(
                server_id=server_id,
                command=command,
                status=audit_status,  # type: ignore[arg-type]
                started_at=started_at,
                finished_at=finished_at,
                principal_id=principal_id,
                source_ip=source_ip,
                confirmed=confirmed,
                exit_code=fd.exit_code if fd else None,
                stdout="".join(stdout_preview_buf),
                stderr="".join(stderr_preview_buf),
                transport="ws",
                aborted=aborted,
                abort_reason=abort_reason,  # type: ignore[arg-type]
                stream_stats={
                    "bytes_stdout": stdout_total,
                    "bytes_stderr": stderr_total,
                    "chunk_count": chunk_count,
                },
            )
            # Release the pool lock so scheduler can proceed on this server
            await _pool_ctx.__aexit__(None, None, None)