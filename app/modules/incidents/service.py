from app.core.database import get_database
from app.modules.incidents.schemas import IncidentStatus
from app.core.events import event_bus
from bson import ObjectId
from datetime import datetime, timezone

_ACTIVE_STATUSES = {
    IncidentStatus.OPEN.value,
    IncidentStatus.VERIFYING.value,
    IncidentStatus.INVESTIGATING.value,
}


class IncidentService:

    async def get_all(
        self,
        server_id: str = None,
        severity: str = None,
        status: str = None,
        search: str = None,
        page: int = 1,
        page_size: int = 20,
    ):
        import re
        db = get_database()

        query = {}
        if server_id:
            query["server_id"] = server_id
        if severity:
            query["severity"] = severity
        if status:
            query["status"] = status
        if search:
            pattern = re.compile(re.escape(search), re.IGNORECASE)
            query["$or"] = [{"description": pattern}, {"rule_id": pattern}]

        total = await db["incidents"].count_documents(query)
        skip = (page - 1) * page_size
        cursor = (
            db["incidents"]
            .find(query)
            .sort("detected_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        incidents = await cursor.to_list(length=page_size)

        for inc in incidents:
            inc["_id"] = str(inc["_id"])

        return {"total": total, "page": page, "page_size": page_size, "results": incidents}

    async def get_by_id(self, incident_id: str):
        db = get_database()

        try:
            oid = ObjectId(incident_id)
        except Exception:
            return None

        incident = await db["incidents"].find_one({"_id": oid})
        if incident:
            incident["_id"] = str(incident["_id"])

        return incident

    async def update_status(self, incident_id: str, new_status: IncidentStatus):
        db = get_database()

        try:
            oid = ObjectId(incident_id)
        except Exception:
            return {"status": "failed", "error": "Invalid Incident ID"}

        # Check it exists
        incident = await db["incidents"].find_one({"_id": oid})
        if not incident:
            return {"status": "failed", "error": "Incident not found"}

        # Prepare update
        update_fields = {"status": new_status.value}

        # Add resolved_at timestamp when resolving or marking as false positive
        if new_status in [IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE]:
            update_fields["resolved_at"] = datetime.now(timezone.utc)

        await db["incidents"].update_one({"_id": oid}, {"$set": update_fields})

        # Adjust server open_incidents_count based on active→terminal or terminal→active
        old_status = incident.get("status")
        new_status_val = new_status.value
        server_id = incident.get("server_id")
        if server_id:
            was_active = old_status in _ACTIVE_STATUSES
            now_active = new_status_val in _ACTIVE_STATUSES
            if was_active and not now_active:
                await db["servers"].update_one(
                    {"_id": ObjectId(server_id)},
                    {"$inc": {"open_incidents_count": -1}},
                )
            elif not was_active and now_active:
                await db["servers"].update_one(
                    {"_id": ObjectId(server_id)},
                    {"$inc": {"open_incidents_count": 1}},
                )
            if was_active != now_active:
                event_bus.emit("servers", "server.updated", {"server_id": server_id})

        # Return updated document
        updated = await db["incidents"].find_one({"_id": oid})
        updated["_id"] = str(updated["_id"])
        return {"status": "success", "incident": updated}

    async def get_stats(self):
        db = get_database()

        # Aggregation pipeline for dashboard stats
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "open": {
                        "$sum": {"$cond": [{"$eq": ["$status", "open"]}, 1, 0]}
                    },
                    "investigating": {
                        "$sum": {
                            "$cond": [{"$eq": ["$status", "investigating"]}, 1, 0]
                        }
                    },
                    "resolved": {
                        "$sum": {"$cond": [{"$eq": ["$status", "resolved"]}, 1, 0]}
                    },
                    "false_positive": {
                        "$sum": {
                            "$cond": [{"$eq": ["$status", "false_positive"]}, 1, 0]
                        }
                    },
                    "critical": {
                        "$sum": {
                            "$cond": [{"$eq": ["$severity", "critical"]}, 1, 0]
                        }
                    },
                    "high": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "high"]}, 1, 0]}
                    },
                    "medium": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "medium"]}, 1, 0]}
                    },
                    "low": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "low"]}, 1, 0]}
                    },
                }
            }
        ]

        result = await db["incidents"].aggregate(pipeline).to_list(length=1)

        if not result:
            return {
                "total": 0,
                "by_status": {
                    "open": 0,
                    "investigating": 0,
                    "resolved": 0,
                    "false_positive": 0,
                },
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }

        r = result[0]
        return {
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
