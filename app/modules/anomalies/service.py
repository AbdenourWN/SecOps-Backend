"""
Anomalies service — CRUD + lifecycle for log_observations.

Observations are records of "interesting" logs/signals that didn't match a
rule but tripped one of the Tier 2 heuristics. They have three terminal
states: dismissed, promoted_to_incident, and (later) ai_analyzed.

This module is deliberately thin — it does not run the heuristics itself
(that's `app.modules.heuristics.service`). It just persists the results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Tuple

from bson import ObjectId

from app.core.database import get_database
from app.core.events import event_bus
from app.modules.anomalies.schemas import (
    AnomalySeverity,
    AnomalyType,
    LogObservationStatus,
    score_to_severity,
)
from app.modules.incidents.schemas import IncidentInDB, SeverityLevel


# Map our anomaly severity (low/med/high) onto the incident SeverityLevel
# (low/medium/high/critical). Anomalies are heuristic, not confirmed — so
# we cap promotion at 'high'.
_SEVERITY_MAP = {
    AnomalySeverity.LOW: SeverityLevel.LOW,
    AnomalySeverity.MEDIUM: SeverityLevel.MEDIUM,
    AnomalySeverity.HIGH: SeverityLevel.HIGH,
}


class AnomaliesService:

    # ────────────────────────────────────────────────────────────────────
    # Write paths
    # ────────────────────────────────────────────────────────────────────

    async def record_log_observation(
        self,
        log: dict,
        server: dict,
        flags: List[Tuple[str, int]],
    ) -> Optional[str]:
        """
        Create a `type=log` observation. Called by analysis service when
        heuristics flag a rule-unmatched log. Returns the new observation id
        (or None if `flags` was empty).
        """
        if not flags:
            return None

        db = get_database()
        reasons = [r for r, _ in flags]
        score = min(sum(s for _, s in flags), 10)
        severity = score_to_severity(score)

        doc = {
            "server_id": str(server["_id"]),
            "type": AnomalyType.LOG.value,
            "log_id": str(log.get("_id")) if log.get("_id") else None,
            "log_message": (log.get("message") or "")[:2000],  # truncate huge lines
            "log_timestamp": log.get("timestamp"),
            "reasons": reasons,
            "score": score,
            "severity": severity.value,
            "status": LogObservationStatus.PENDING_REVIEW.value,
            "promoted_incident_id": None,
            "detected_at": datetime.now(timezone.utc),
            "reviewed_at": None,
        }
        result = await db["log_observations"].insert_one(doc)
        observation_id = str(result.inserted_id)

        event_bus.emit("anomalies", "anomaly.created", {
            "observation_id": observation_id,
            "server_id": doc["server_id"],
            "severity": severity.value,
            "type": AnomalyType.LOG.value,
            "reasons": reasons,
        })
        event_bus.emit(f"servers.{doc['server_id']}.anomalies", "anomaly.created", {  # deprecated: remove when RBAC lands
            "observation_id": observation_id,
            "server_id": doc["server_id"],
            "severity": severity.value,
            "type": AnomalyType.LOG.value,
            "reasons": reasons,
        })
        return observation_id

    async def record_volume_observation(
        self,
        server: dict,
        current: int,
        baseline: float,
        reason: str,
    ) -> str:
        """
        Create a `type=volume` observation when the EMA spike check fires.
        """
        db = get_database()
        # Volume spikes are inherently noteworthy; force at least medium.
        score = max(3, min(int(round(current / max(baseline, 1))), 10))
        severity = score_to_severity(score)

        doc = {
            "server_id": str(server["_id"]),
            "type": AnomalyType.VOLUME.value,
            "log_id": None,
            "log_message": f"Log rate spike: {current} logs/min vs baseline {baseline:.1f}",
            "log_timestamp": datetime.now(timezone.utc),
            "reasons": [reason],
            "score": score,
            "severity": severity.value,
            "status": LogObservationStatus.PENDING_REVIEW.value,
            "promoted_incident_id": None,
            "detected_at": datetime.now(timezone.utc),
            "reviewed_at": None,
        }
        result = await db["log_observations"].insert_one(doc)
        observation_id = str(result.inserted_id)

        event_bus.emit("anomalies", "anomaly.created", {
            "observation_id": observation_id,
            "server_id": doc["server_id"],
            "severity": severity.value,
            "type": AnomalyType.VOLUME.value,
            "reasons": [reason],
        })
        event_bus.emit(f"servers.{doc['server_id']}.anomalies", "anomaly.created", {  # deprecated: remove when RBAC lands
            "observation_id": observation_id,
            "server_id": doc["server_id"],
            "severity": severity.value,
            "type": AnomalyType.VOLUME.value,
            "reasons": [reason],
        })
        return observation_id

    # ────────────────────────────────────────────────────────────────────
    # Read paths
    # ────────────────────────────────────────────────────────────────────

    def _build_filter(
        self,
        server_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        type_: Optional[str] = None,
    ) -> dict:
        q: dict = {}
        if server_id:
            q["server_id"] = server_id
        if status and status != "all":
            q["status"] = status
        if severity and severity != "all":
            q["severity"] = severity
        if type_ and type_ != "all":
            q["type"] = type_
        return q

    async def list(
        self,
        page: int = 1,
        page_size: int = 25,
        server_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        type_: Optional[str] = None,
    ):
        db = get_database()
        q = self._build_filter(server_id, status, severity, type_)

        total = await db["log_observations"].count_documents(q)
        skip = (page - 1) * page_size

        cursor = (
            db["log_observations"]
            .find(q)
            .sort("detected_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        rows = await cursor.to_list(length=page_size)

        # Enrich with hostname (single batch lookup)
        sids = list({r["server_id"] for r in rows if r.get("server_id")})
        oids = []
        for sid in sids:
            try:
                oids.append(ObjectId(sid))
            except Exception:
                pass

        host_map: dict = {}
        if oids:
            host_docs = await db["servers"].find(
                {"_id": {"$in": oids}}, {"hostname": 1}
            ).to_list(length=len(oids))
            host_map = {str(d["_id"]): d.get("hostname", "") for d in host_docs}

        results = []
        for r in rows:
            r["_id"] = str(r["_id"])
            r["server_hostname"] = host_map.get(r["server_id"], "")
            results.append(r)

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "results": results,
        }

    async def stats(self) -> dict:
        db = get_database()
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "pending": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$status", LogObservationStatus.PENDING_REVIEW.value]},
                                1, 0,
                            ]
                        }
                    },
                    "dismissed": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$status", LogObservationStatus.DISMISSED.value]},
                                1, 0,
                            ]
                        }
                    },
                    "promoted": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$status", LogObservationStatus.PROMOTED_TO_INCIDENT.value]},
                                1, 0,
                            ]
                        }
                    },
                }
            }
        ]
        agg = await db["log_observations"].aggregate(pipeline).to_list(length=1)
        if not agg:
            return {"total": 0, "pending": 0, "dismissed": 0, "promoted": 0}
        r = agg[0]
        return {k: r.get(k, 0) for k in ("total", "pending", "dismissed", "promoted")}

    # ────────────────────────────────────────────────────────────────────
    # Lifecycle: dismiss / promote
    # ────────────────────────────────────────────────────────────────────

    async def dismiss(self, observation_id: str) -> bool:
        db = get_database()
        try:
            oid = ObjectId(observation_id)
        except Exception:
            return False

        result = await db["log_observations"].update_one(
            {"_id": oid, "status": LogObservationStatus.PENDING_REVIEW.value},
            {"$set": {
                "status": LogObservationStatus.DISMISSED.value,
                "reviewed_at": datetime.now(timezone.utc),
            }},
        )
        if result.modified_count:
            obs = await db["log_observations"].find_one({"_id": oid}, {"server_id": 1})
            _sid = obs.get("server_id") if obs else None
            event_bus.emit("anomalies", "anomaly.updated", {
                "observation_id": observation_id,
                "server_id": _sid,
                "status": LogObservationStatus.DISMISSED.value,
            })
            if _sid:
                event_bus.emit(f"servers.{_sid}.anomalies", "anomaly.updated", {  # deprecated: remove when RBAC lands
                    "observation_id": observation_id,
                    "server_id": _sid,
                    "status": LogObservationStatus.DISMISSED.value,
                })
            return True
        return False

    async def promote_to_incident(self, observation_id: str) -> Optional[str]:
        """
        Promote a pending observation to a real incident. Returns the new
        incident_id. The observation transitions to PROMOTED_TO_INCIDENT and
        carries `promoted_incident_id` for traceability.
        """
        db = get_database()
        try:
            oid = ObjectId(observation_id)
        except Exception:
            return None

        obs = await db["log_observations"].find_one({"_id": oid})
        if not obs or obs.get("status") != LogObservationStatus.PENDING_REVIEW.value:
            return None

        sev = AnomalySeverity(obs.get("severity", "low"))
        incident_severity = _SEVERITY_MAP.get(sev, SeverityLevel.LOW)

        reasons_str = ", ".join(obs.get("reasons", [])) or "manual promotion"
        description = f"Anomaly promoted: {reasons_str}"

        incident = IncidentInDB(
            server_id=obs["server_id"],
            rule_id="anomaly:promoted",   # synthetic — denotes manual promotion
            log_id=obs.get("log_id") or "",
            severity=incident_severity,
            description=description,
            context={
                "source": "anomaly",
                "observation_id": observation_id,
                "reasons": obs.get("reasons", []),
                "log_message": (obs.get("log_message") or "")[:500],
            },
        )
        inc_result = await db["incidents"].insert_one(incident.model_dump())
        incident_id = str(inc_result.inserted_id)

        await db["log_observations"].update_one(
            {"_id": oid},
            {"$set": {
                "status": LogObservationStatus.PROMOTED_TO_INCIDENT.value,
                "promoted_incident_id": incident_id,
                "reviewed_at": datetime.now(timezone.utc),
            }},
        )

        event_bus.emit("anomalies", "anomaly.updated", {
            "observation_id": observation_id,
            "server_id": obs["server_id"],
            "status": LogObservationStatus.PROMOTED_TO_INCIDENT.value,
            "promoted_incident_id": incident_id,
        })
        event_bus.emit(f"servers.{obs['server_id']}.anomalies", "anomaly.updated", {  # deprecated: remove when RBAC lands
            "observation_id": observation_id,
            "server_id": obs["server_id"],
            "status": LogObservationStatus.PROMOTED_TO_INCIDENT.value,
            "promoted_incident_id": incident_id,
        })
        event_bus.emit("incidents", "incident.created", {
            "incident_id": incident_id,
            "server_id": obs["server_id"],
            "severity": incident_severity.value,
            "rule_name": "Anomaly (promoted)",
            "action_level": 3,
        })
        event_bus.emit(f"servers.{obs['server_id']}.incidents", "incident.created", {  # deprecated: remove when RBAC lands
            "incident_id": incident_id,
            "server_id": obs["server_id"],
            "severity": incident_severity.value,
            "rule_name": "Anomaly (promoted)",
            "action_level": 3,
        })
        event_bus.emit("dashboard.summary", "incident.created", {"incident_id": incident_id})

        return incident_id
