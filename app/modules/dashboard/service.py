from app.core.database import get_database
from datetime import datetime, timezone, timedelta


class DashboardService:

    async def get_summary(self):
        """
        Single endpoint that returns the full dashboard overview.
        Pulls data from: servers, incidents, metrics, logs, scripts, rules.
        """
        db = get_database()

        # --- Counts ---
        total_servers = await db["servers"].count_documents({})
        online_servers = await db["servers"].count_documents({"status": "online"})
        offline_servers = await db["servers"].count_documents({"status": "offline"})
        total_rules = await db["rules"].count_documents({"enabled": True})
        total_scripts = await db["scripts"].count_documents({})

        # --- Incident Stats (Aggregation) ---
        inc_pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "open": {"$sum": {"$cond": [{"$eq": ["$status", "open"]}, 1, 0]}},
                    "investigating": {"$sum": {"$cond": [{"$eq": ["$status", "investigating"]}, 1, 0]}},
                    "resolved": {"$sum": {"$cond": [{"$eq": ["$status", "resolved"]}, 1, 0]}},
                    "false_positive": {"$sum": {"$cond": [{"$eq": ["$status", "false_positive"]}, 1, 0]}},
                    "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "critical"]}, 1, 0]}},
                    "high": {"$sum": {"$cond": [{"$eq": ["$severity", "high"]}, 1, 0]}},
                    "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "medium"]}, 1, 0]}},
                    "low": {"$sum": {"$cond": [{"$eq": ["$severity", "low"]}, 1, 0]}},
                }
            }
        ]
        inc_result = await db["incidents"].aggregate(inc_pipeline).to_list(length=1)

        if inc_result:
            r = inc_result[0]
            incidents = {
                "total": r["total"],
                "by_status": {
                    "open": r["open"],
                    "investigating": r["investigating"],
                    "resolved": r["resolved"],
                    "false_positive": r["false_positive"],
                },
                "by_severity": {
                    "critical": r["critical"],
                    "high": r["high"],
                    "medium": r["medium"],
                    "low": r["low"],
                },
            }
        else:
            incidents = {
                "total": 0,
                "by_status": {"open": 0, "investigating": 0, "resolved": 0, "false_positive": 0},
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }

        # --- Log Stats (Last 24h) ---
        last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        logs_last_24h = await db["logs"].count_documents({"ingested_at": {"$gte": last_24h}})
        total_logs = await db["logs"].count_documents({})

        return {
            "servers": {
                "total": total_servers,
                "online": online_servers,
                "offline": offline_servers,
            },
            "incidents": incidents,
            "logs": {
                "total": total_logs,
                "last_24h": logs_last_24h,
            },
            "rules": total_rules,
            "scripts": total_scripts,
        }

    async def get_recent_incidents(self, limit: int = 10):
        """
        Returns the most recent incidents for the dashboard feed.
        Enriched with server hostname for display.
        """
        db = get_database()

        # Fetch recent incidents
        cursor = db["incidents"].find().sort("detected_at", -1).limit(limit)
        incidents = await cursor.to_list(length=limit)

        # Enrich with server hostname (batch lookup)
        from bson import ObjectId

        server_ids = list(set(inc.get("server_id") for inc in incidents if inc.get("server_id")))
        servers = {}
        for sid in server_ids:
            try:
                server = await db["servers"].find_one({"_id": ObjectId(sid)})
                if server:
                    servers[sid] = server.get("hostname", "Unknown")
            except Exception:
                pass

        # Format response
        result = []
        for inc in incidents:
            inc["_id"] = str(inc["_id"])
            inc["server_hostname"] = servers.get(inc.get("server_id", ""), "Unknown")
            result.append(inc)

        return result

    async def get_server_health(self):
        """
        Returns all servers with their latest metric snapshot.
        """
        db = get_database()

        servers = await db["servers"].find().to_list(length=100)
        result = []

        for server in servers:
            server_id = str(server["_id"])
            server["_id"] = server_id

            # Fetch latest metric for this server
            latest_metric = await db["metrics"].find_one(
                {"server_id": server_id},
                sort=[("timestamp", -1)]
            )

            # Fetch open incident count for this server
            open_incidents = await db["incidents"].count_documents({
                "server_id": server_id,
                "status": {"$in": ["open", "investigating"]}
            })

            result.append({
                "server": server,
                "latest_metric": {
                    "cpu_usage": latest_metric.get("cpu_usage") if latest_metric else None,
                    "ram_usage": latest_metric.get("ram_usage") if latest_metric else None,
                    "disk_usage": latest_metric.get("disk_usage") if latest_metric else None,
                    "timestamp": latest_metric.get("timestamp") if latest_metric else None,
                } if latest_metric else None,
                "open_incidents": open_incidents,
            })

        return result
