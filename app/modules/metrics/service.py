from app.core.database import get_database
from app.core.elasticsearch import get_elasticsearch
from app.core.events import event_bus
from app.modules.metrics.schemas import SystemMetric
from app.core.executors import get_server_executor
from app.core.security import decrypt_password
from bson import ObjectId
from datetime import datetime, timezone
import uuid

def _get_metric_index_name():
    now = datetime.now(timezone.utc)
    return f"secops-metrics-{now.strftime('%Y.%m')}"

class MetricService:
    
    async def collect_with(self, executor, server: dict) -> bool:
        """
        Collect metrics using a pre-resolved pooled executor.
        Called by the combined scheduler job (no credential lookup needed).
        """
        server_id = str(server["_id"])
        os_type = server.get("os_type", "linux")

        if os_type == "windows":
            cmd = (
                "$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; "
                "if (!$cpu) { $cpu = 0 }; "
                "$os = Get-CimInstance Win32_OperatingSystem; "
                "$mem = 0; "
                "if ($os.TotalVisibleMemorySize -gt 0) { $mem = (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100 }; "
                "$disk = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }; "
                "$disk_usage = 0; "
                "if ($disk) { $disk_usage = (($disk.Size - $disk.FreeSpace) / $disk.Size) * 100 }; "
                "Write-Output \"$cpu,$mem,$disk_usage\""
            )
        else:
            cmd = (
                "cpu=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'); "
                "mem=$(free | grep Mem | awk '{print $3/$2 * 100.0}'); "
                "disk=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//'); "
                "echo \"$cpu,$mem,$disk\""
            )

        result = await executor.run_command(cmd)

        if result["status"] == "failed":
            print(f"❌ Metrics failed for {server.get('hostname')}: {result.get('error')}")
            return False

        try:
            output = result["output"].strip()
            if not output:
                return False
            if "," not in output and "\n" in output:
                output = output.replace("\r", "").replace("\n", ",")
            parts = output.split(",")
            if len(parts) < 3:
                parts.extend([0] * (3 - len(parts)))

            cpu_val = float(parts[0]) if parts[0] else 0.0
            ram_val = float(parts[1]) if parts[1] else 0.0
            disk_val = float(parts[2]) if parts[2] else 0.0

            metric_doc = {
                "server_id": server_id,
                "cpu_usage": round(cpu_val, 2),
                "ram_usage": round(ram_val, 2),
                "disk_usage": round(disk_val, 2),
                "raw_data": output,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            es = get_elasticsearch()
            if es:
                try:
                    await es.index(
                        index=_get_metric_index_name(),
                        id=str(uuid.uuid4()),
                        document=metric_doc,
                    )
                except Exception as e:
                    print(f"⚠️ Failed to index metric to ES: {e}")

            event_bus.emit("servers.metrics", "metric.sampled", {
                "server_id": server_id,
                "cpu_usage": metric_doc["cpu_usage"],
                "ram_usage": metric_doc["ram_usage"],
                "disk_usage": metric_doc["disk_usage"],
                "timestamp": metric_doc["timestamp"],
            })
            return True
        except Exception as e:
            print(f"⚠️ Parsing Error for {server.get('hostname')}: {e}")
            return False

    async def collect_metrics(self, server_id: str):
        """Backwards-compatible wrapper — resolves executor from DB then delegates to collect_with."""
        db = get_database()
        try:
            s_oid = ObjectId(server_id)
        except Exception:
            return False
        server = await db["servers"].find_one({"_id": s_oid})
        if not server:
            return False
        cred = await db["credentials"].find_one({"_id": ObjectId(server["credential_id"])})
        if not cred:
            return False
        plain_secret = decrypt_password(cred["encrypted_secret"])
        executor = get_server_executor(server, plain_secret)
        executor.credential["username"] = cred["username"]
        return await self.collect_with(executor, server)

    async def get_latest_metrics(self, server_id: str, limit: int = 20):
        """Get history for charts from Elasticsearch"""
        es = get_elasticsearch()
        if not es:
            return []
            
        try:
            result = await es.search(
                index="secops-metrics-*",
                body={
                    "query": {
                        "term": {"server_id": server_id}
                    },
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": limit
                }
            )
            
            metrics = []
            for hit in result["hits"]["hits"]:
                doc = hit["_source"]
                doc["_id"] = hit["_id"]
                metrics.append(doc)
                
            return metrics
        except Exception as e:
            print(f"⚠️ ES search error: {e}")
            return []