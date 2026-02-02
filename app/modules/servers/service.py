import paramiko
import asyncio

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