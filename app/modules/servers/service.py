import asyncio
from app.core.database import get_database
from app.modules.servers.schemas import ServerCreate, ServerInDB, CredentialInDB, ServerUpdate, ServerDelete, ServerStatus
from app.core.security import encrypt_password, decrypt_password
from bson import ObjectId
from datetime import datetime ,timezone
from app.core.executors import get_server_executor
from app.core.rate_limit import check_rate_limit
from app.modules.servers.guardrails import check_command
from app.modules.servers.audit import write_audit
from app.core.events import event_bus


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
            import asyncio
            from app.core.config import settings
            from app.core.scheduler import _get_server_lock

            db = get_database()
            servers = await db["servers"].find().to_list(length=10000)
            print(f"🕵️  Starting Health Check Cycle...")
            
            sem = asyncio.Semaphore(settings.MAX_CONCURRENT_SERVERS)

            async def check_one(server):
                server_id = str(server["_id"])
                previous_status = server.get("status")
                async with sem:
                    async with _get_server_lock(server_id):
                        executor = get_server_executor(server, plain_password="")
                        is_online = await executor.check_health()
                        new_status = ServerStatus.ONLINE if is_online else ServerStatus.OFFLINE

                        await db["servers"].update_one(
                            {"_id": server["_id"]},
                            {
                                "$set": {
                                    "status": new_status,
                                    "last_health_check": datetime.now(timezone.utc)
                                }
                            }
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
        # Delete the Server
        await db["servers"].delete_one({"_id": oid})
        # Delete the Linked Credential
        await db["credentials"].delete_one({"_id": cred_id})

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

        # --- 3. Resolve credential and run ---
        cred_id = server.get("credential_id")
        try:
            s_c_oid = ObjectId(cred_id)
        except Exception:
            return {"status": "failed", "error": "Invalid Credential ID"}

        credential = await db["credentials"].find_one({"_id": s_c_oid})
        if not credential:
            return {"status": "failed", "error": "Linked credential not found"}

        try:
            plain_secret = decrypt_password(credential["encrypted_secret"])
        except Exception:
            return {"status": "failed", "error": "Decryption failed"}

        executor = get_server_executor(server, plain_password=plain_secret)
        executor.credential['username'] = credential['username']

        effective_timeout = DEFAULT_COMMAND_TIMEOUT_S if timeout_s is None else \
            max(1, min(MAX_COMMAND_TIMEOUT_S, int(timeout_s)))

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

        # Logic for 'ssh_key' file handling will be added later.