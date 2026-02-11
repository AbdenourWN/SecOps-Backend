from app.core.database import get_database
from app.modules.metrics.schemas import SystemMetric
from app.core.executors import get_server_executor
from app.core.security import decrypt_password
from bson import ObjectId

class MetricService:
    
    async def collect_metrics(self, server_id: str):
        db = get_database()
        
        # 1. Fetch Server
        try:
            s_oid = ObjectId(server_id)
        except:
            return False
            
        server = await db["servers"].find_one({"_id": s_oid})
        if not server:
            return False
        
        # 2. Setup Executor
        cred = await db["credentials"].find_one({"_id": ObjectId(server["credential_id"])})
        if not cred:
            print(f"❌ Credential missing for server {server.get('hostname')}")
            return False
            
        plain_secret = decrypt_password(cred["encrypted_secret"])
        
        executor = get_server_executor(server, plain_secret)
        executor.credential['username'] = cred['username']

        # 3. Define Command based on OS
        cmd = ""
        if server.get("os_type") == "windows":
            # WINDOWS COMMAND (PowerShell)
            # Fix: We removed the WMI Filter "DeviceID='C:'" because of quoting issues.
            # We now grab ALL disks and filter for C: using Where-Object (Safer).
            cmd = (
                "$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; "
                "if (!$cpu) { $cpu = 0 }; "
                "$os = Get-CimInstance Win32_OperatingSystem; "
                "$mem = 0; "
                "if ($os.TotalVisibleMemorySize -gt 0) { $mem = (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100 }; "
                # -- CHANGED LINE BELOW --
                "$disk = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }; "
                "$disk_usage = 0; "
                "if ($disk) { $disk_usage = (($disk.Size - $disk.FreeSpace) / $disk.Size) * 100 }; "
                "Write-Output \"$cpu,$mem,$disk_usage\""
            )
        else:
            # LINUX COMMAND (Bash)
            cmd = (
                "cpu=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'); "
                "mem=$(free | grep Mem | awk '{print $3/$2 * 100.0}'); "
                "disk=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//'); "
                "echo \"$cpu,$mem,$disk\""
            )
        
        # 4. Execute
        result = await executor.run_command(cmd)
        
        if result["status"] == "failed":
            print(f"❌ Metrics failed for {server['hostname']}: {result.get('error')}")
            return False

        # 5. Parse Output
        try:
            output = result["output"].strip()
            
            # Sanity check: ensure we got data
            if not output: return False
            
            # Fallback cleanup: If PowerShell added newlines instead of commas (rare but possible), fix it
            if "," not in output and "\n" in output:
                 output = output.replace("\r", "").replace("\n", ",")
            
            parts = output.split(',')
            
            # Additional safety: ensure we have 3 parts
            if len(parts) < 3:
                # Pad with 0s if something is missing
                parts.extend([0] * (3 - len(parts)))
            
            cpu_val = float(parts[0]) if parts[0] else 0.0
            ram_val = float(parts[1]) if parts[1] else 0.0
            disk_val = float(parts[2]) if parts[2] else 0.0
            
            # 6. Save to DB
            metric = SystemMetric(
                server_id=str(server["_id"]),
                cpu_usage=round(cpu_val, 2),
                ram_usage=round(ram_val, 2),
                disk_usage=round(disk_val, 2),
                raw_data=output
            )
            
            await db["metrics"].insert_one(metric.model_dump())
            return True
            
        except Exception as e:
            print(f"⚠️ Parsing Error for {server['hostname']}: Output='{result.get('output')}' | Error={e}")
            return False

    async def get_latest_metrics(self, server_id: str, limit: int = 20):
        """Get history for charts"""
        db = get_database()
        cursor = db["metrics"].find({"server_id": server_id}).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)