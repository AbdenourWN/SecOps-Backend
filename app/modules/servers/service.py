import paramiko
import asyncio
from app.core.database import get_database
from app.modules.servers.schemas import ServerCreate, ServerInDB, CredentialInDB, ServerUpdate, ServerDelete, ServerStatus
from app.core.security import encrypt_password, decrypt_password
from bson import ObjectId
from datetime import datetime ,timezone



class ServerService:
    async def run_command(self, ip: str, username: str, password: str, command: str):
        """
        Connects via SSH and runs a command on the remote server.
        """
        def _ssh_task():
            client = paramiko.SSHClient()
            # ⚠️ SECURITY WARNING: This automatically trusts the server. 
            # In production, we should verify the host key. For now, it's fine.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                print(f"🔌 Connecting to {ip}...")
                # 1. Connect
                client.connect(hostname=ip, username=username, password=password, timeout=10)
                
                # 2. Run Command
                print(f"🚀 Executing: {command}")
                stdin, stdout, stderr = client.exec_command(command)
                
                # 3. Read Output
                result = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                
                client.close()
                
                if error:
                    return {"status": "error", "output": error}
                return {"status": "success", "output": result}
                
            except Exception as e:
                print(f"❌ Error: {str(e)}")
                return {"status": "failed", "error": str(e)}

        # Run the slow SSH connection in a separate thread so FastAPI doesn't freeze
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _ssh_task)
        return result
    

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
    


    async def is_server_reachable(self, ip: str, port: int = 22) -> bool:
        """
        Checks if a TCP port is open. Fast and lightweight.
        """
        try:
            # Try to open a connection with a 3-second timeout
            # We don't send data, just check if the door opens.
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=3)
            
            # If successful, close immediately
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def update_all_server_statuses(self):
            """
            Scans ALL servers using a Cursor (Memory Safe).
            """
            db = get_database()
            
            # 1. Use an async cursor instead of to_list()
            # This allows handling 100,000+ servers without crashing RAM
            cursor = db["servers"].find()
            
            print(f"🕵️  Starting Health Check Cycle...")
            
            count = 0
            async for server in cursor:
                ip = server["ip_address"]
                server_id = server["_id"]
                
                # 2. Check status
                is_online = await self.is_server_reachable(ip)
                
                # Logic for future: 
                # If (is_online) AND (cpu_usage > 90): status = WARNING
                # For now, just Online/Offline
                new_status = ServerStatus.ONLINE if is_online else ServerStatus.OFFLINE
                
                # 3. Update DB
                await db["servers"].update_one(
                    {"_id": server_id},
                    {
                        "$set": {
                            "status": new_status, 
                            "last_health_check": datetime.now(timezone.utc)
                        }
                    }
                )
                count += 1
                
            print(f"✅ Health Check Complete. Scanned {count} servers.")
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
            credential_id=str(new_cred_id)
        )

        # Save Server to "servers" collection
        server_result = await db["servers"].insert_one(server_in_db.model_dump())
        
        return {
            "status": "success", 
            "server_id": str(server_result.inserted_id),
            "credential_id": str(new_cred_id)
        }
    
    async def get_all_servers(self, limit: int = 100):
        db = get_database()
        # Fetch servers. limit(100) prevents crashing if you have 1 million servers
        servers = await db["servers"].find().to_list(limit)
        return servers

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
        
        return {"status": "success", "message": "Server and associated credentials deleted"}
    


    async def execute_command_by_id(self, server_id: str, command: str):
        db = get_database()

        
        # 1. Find the Server
        try:
            s_oid = ObjectId(server_id)
        except:
            return {"status": "failed", "error": "Invalid Server ID"}

        server = await db["servers"].find_one({"_id": s_oid})
        if not server:
            return {"status": "failed", "error": "Server not found"}

        # 2. Find the Linked Credential
        cred_id = server.get("credential_id")
        try:
            s_c_oid = ObjectId(cred_id)
        except:
            return {"status": "failed", "error": "Invalid Credential ID"}

        credential = await db["credentials"].find_one({"_id": s_c_oid})
        
        if not credential:
            return {"status": "failed", "error": "Linked credential not found"}

        # 3. Decrypt Secret
        try:
            plain_secret = decrypt_password(credential["encrypted_secret"])
        except Exception:
            return {"status": "failed", "error": "Decryption failed"}

        # 4. Execute
        # Note: We currently assume 'password' type. 
        return await self.run_command(
            ip=server["ip_address"],
            username=credential["username"],
            password=plain_secret,
            command=command
        )
    
        # Logic for 'ssh_key' file handling will be added later.