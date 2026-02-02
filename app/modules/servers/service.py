import paramiko
import asyncio
from app.core.database import get_database
from app.modules.servers.schemas import ServerCreate, ServerInDB
from app.core.security import encrypt_password
from uuid import UUID
from app.core.security import decrypt_password
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
    
    async def create_server(self, server_data: ServerCreate) -> dict:
        db = get_database()
        
        # Check if server with this IP already exists
        if await db["servers"].find_one({"ip_address": server_data.ip_address}):
            return {"status": "failed", "error": "Server with this IP already exists"}

        # Encrypt the password before storing
        encrypted_pass = encrypt_password(server_data.password)
        
        # Create the object we will store in the DB
        server_in_db = ServerInDB(
            hostname=server_data.hostname,
            ip_address=server_data.ip_address,
            os_type=server_data.os_type,
            username=server_data.username,
            encrypted_password=encrypted_pass
        )

        # Insert into MongoDB
        result = await db["servers"].insert_one(server_in_db.model_dump(by_alias=True))
        
        return {"status": "success", "inserted_id": str(result.inserted_id)}
    
    async def get_all_servers(self, limit: int = 100):
        db = get_database()
        # Fetch servers. limit(100) prevents crashing if you have 1 million servers
        servers = await db["servers"].find().to_list(limit)
        return servers

    async def get_server(self, server_id: UUID):
        db = get_database()
        # Find by the UUID (_id)
        server = await db["servers"].find_one({"_id": server_id})
        return server

    async def execute_command_by_id(self, server_id: UUID, command: str):
        # 1. Get the server from DB
        server = await self.get_server(server_id)
        if not server:
            return {"status": "failed", "error": "Server not found"}

        # 2. Decrypt the password
        try:
            encrypted_pass = server["encrypted_password"]
            plain_password = decrypt_password(encrypted_pass)
        except Exception as e:
            return {"status": "failed", "error": f"Decryption failed: {str(e)}"}

        # 3. Reuse the existing run_command function
        return await self.run_command(
            ip=server["ip_address"],
            username=server["username"],
            password=plain_password,
            command=command
        )