import paramiko
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

# --- 1. The Blueprint (Abstract Base Class) ---
class BaseExecutor(ABC):
    def __init__(self, ip: str, port: int, credential: Optional[Dict[str, str]] = None):
        self.ip = ip
        self.port = port
        self.credential = credential or {}

    @abstractmethod
    async def run_command(self, command: str) -> Dict[str, Any]:
        """Execute a shell command and return {status, output, error}"""
        pass

    @abstractmethod
    async def check_health(self) -> bool:
        """Check if the specific service is responding (Ping/TCP)"""
        pass

# --- 2. The Linux Specialist (SSH) ---
class LinuxExecutor(BaseExecutor):
    async def run_command(self, command: str) -> Dict[str, Any]:
        
        # We define the blocking SSH code inside this inner function
        def _ssh_task():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                # Extract credentials
                username = self.credential.get('username')
                password = self.credential.get('password') # This expects the PLAIN text password

                print(f"🔌 Executor connecting to {self.ip}...")
                client.connect(
                    hostname=self.ip, 
                    port=self.port, 
                    username=username, 
                    password=password, 
                    timeout=10
                )
                
                print(f"🚀 Executing: {command}")
                stdin, stdout, stderr = client.exec_command(command)
                result = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                client.close()
                
                if error:
                    return {"status": "error", "output": error}
                return {"status": "success", "output": result}
                
            except Exception as e:
                print(f"❌ Executor Error: {str(e)}")
                return {"status": "failed", "error": str(e)}

        # We run the blocking code in a separate thread so the API stays fast
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _ssh_task)

    async def check_health(self) -> bool:
        """
        Simple TCP Handshake. 
        Does not need credentials, just checks if port is open.
        """
        try:
            future = asyncio.open_connection(self.ip, self.port)
            reader, writer = await asyncio.wait_for(future, timeout=3)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

# --- 3. The Windows Specialist (Future Proofing) ---
class WindowsExecutor(BaseExecutor):
    async def run_command(self, command: str) -> Dict[str, Any]:
        return {"status": "failed", "error": "Windows WinRM not implemented yet"}

    async def check_health(self) -> bool:
        # Windows usually listens on 5985 for WinRM
        try:
            future = asyncio.open_connection(self.ip, self.port)
            reader, writer = await asyncio.wait_for(future, timeout=3)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

# --- 4. The Factory (The Decision Maker) ---
def get_server_executor(server_doc: Dict, plain_password: str = "") -> BaseExecutor:
    """
    Decides which Executor to use based on the 'os_type' in the server document.
    """
    os_type = server_doc.get("os_type", "linux")
    ip = server_doc["ip_address"]
    port = server_doc.get("port", 22)
    
    # Bundle the credentials into a simple dict
    # (The Service extracts the username/password before calling this)
    creds = {
        "username": "unknown", # Service must set this if needed
        "password": plain_password
    }
    
    if os_type == "windows":
        return WindowsExecutor(ip, port, creds)
    else:
        return LinuxExecutor(ip, port, creds)