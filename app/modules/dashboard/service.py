from app.core.database import get_database
from app.core.elasticsearch import get_elasticsearch
from datetime import datetime, timezone, timedelta


class DashboardService:

    async def _get_es_log_counts(self):
        """
        Gets log counts from Elasticsearch.
        Returns (total_logs, logs_last_24h).
        """
        es = get_elasticsearch()
        if not es:
            return 0, 0

        try:
            # Total logs = count all documents in secops-logs-* indices
            total_result = await es.count(index="secops-logs-*")
            total_logs = total_result["count"]

            # Last 24h = count with date range filter
            last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_result = await es.count(
                index="secops-logs-*",
                body={
                    "query": {
                        "range": {
                            "ingested_at": {"gte": last_24h.isoformat()}
                        }
                    }
                }
            )
            logs_last_24h = recent_result["count"]

            return total_logs, logs_last_24h
        except Exception:
            return 0, 0

    async def get_summary(self):
        """
        Single endpoint that returns the full dashboard overview.
        Pulls data from: servers, incidents, metrics, logs (ES), scripts, rules.
        """
        db = get_database()

        # --- Counts ---
        # Server status is tri-state since Phase 26:
        #   online    — TCP reachable AND credentials work (full health)
        #   reachable — TCP reachable BUT credentials/auth probe failed
        #   offline   — TCP/banner-grab failed
        total_servers = await db["servers"].count_documents({})
        online_servers = await db["servers"].count_documents({"status": "online"})
        reachable_servers = await db["servers"].count_documents({"status": "reachable"})
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

        # --- Log Stats from Elasticsearch ---
        total_logs, logs_last_24h = await self._get_es_log_counts()

        return {
            "servers": {
                "total": total_servers,
                "online": online_servers,
                "reachable": reachable_servers,
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

        cursor = db["incidents"].find().sort("detected_at", -1).limit(limit)
        incidents = await cursor.to_list(length=limit)

        # OPT-6: Batch lookup — 1 query for all server hostnames instead of N
        from bson import ObjectId

        server_ids = list(set(inc.get("server_id") for inc in incidents if inc.get("server_id")))
        oid_list = []
        for sid in server_ids:
            try:
                oid_list.append(ObjectId(sid))
            except Exception:
                pass

        servers = {}
        if oid_list:
            server_docs = await db["servers"].find(
                {"_id": {"$in": oid_list}},
                {"hostname": 1}
            ).to_list(length=100)
            servers = {str(s["_id"]): s.get("hostname", "Unknown") for s in server_docs}

        result = []
        for inc in incidents:
            inc["_id"] = str(inc["_id"])
            inc["server_hostname"] = servers.get(inc.get("server_id", ""), "Unknown")
            result.append(inc)

        return result

    async def get_server_health(self):
        """
        Returns all servers with their latest metric snapshot.
        OPT-6: Batch queries instead of N+1.
        """
        db = get_database()

        servers = await db["servers"].find().to_list(length=100)
        if not servers:
            return []

        server_ids = [str(s["_id"]) for s in servers]

        # ============================================================
        # OPT-6A: BATCH METRICS — 1 ES msearch instead of N searches
        # msearch sends multiple search requests in a single HTTP call
        # ============================================================
        metrics_map = {}
        es = get_elasticsearch()
        if es:
            try:
                search_body = []
                for sid in server_ids:
                    search_body.append({"index": "secops-metrics-*"})
                    search_body.append({
                        "query": {"term": {"server_id": sid}},
                        "sort": [{"timestamp": {"order": "desc"}}],
                        "size": 1
                    })
                
                if search_body:
                    ms_result = await es.msearch(body=search_body)
                    for i, response in enumerate(ms_result["responses"]):
                        if response.get("hits", {}).get("hits"):
                            metrics_map[server_ids[i]] = response["hits"]["hits"][0]["_source"]
            except Exception:
                pass

        # ============================================================
        # OPT-6B: BATCH INCIDENTS — 1 aggregation instead of N counts
        # ============================================================
        incident_counts = {}
        try:
            pipeline = [
                {"$match": {"status": {"$in": ["open", "investigating"]}}},
                {"$group": {"_id": "$server_id", "count": {"$sum": 1}}}
            ]
            counts = await db["incidents"].aggregate(pipeline).to_list(length=1000)
            incident_counts = {c["_id"]: c["count"] for c in counts}
        except Exception:
            pass

        # Build response
        result = []
        for server in servers:
            server_id = str(server["_id"])
            server["_id"] = server_id

            latest_metric = metrics_map.get(server_id)

            result.append({
                "server": server,
                "latest_metric": {
                    "cpu_usage": latest_metric.get("cpu_usage") if latest_metric else None,
                    "ram_usage": latest_metric.get("ram_usage") if latest_metric else None,
                    "disk_usage": latest_metric.get("disk_usage") if latest_metric else None,
                    "timestamp": latest_metric.get("timestamp") if latest_metric else None,
                } if latest_metric else None,
                "open_incidents": incident_counts.get(server_id, 0),
            })

        return result
