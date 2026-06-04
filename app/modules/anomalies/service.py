"""
Anomalies service — CRUD + lifecycle for log_observations.

Observations are records of "interesting" logs/signals that didn't match a
rule but tripped one of the Tier 2 heuristics.  They have three terminal
states: dismissed, promoted_to_incident, and (later) ai_analyzed.

Deduplication: within a per-server configurable window (default 2h), identical
observations (same fingerprint) are aggregated into a single row instead of
creating new rows.  The first occurrence fires an `anomaly.created` event;
subsequent ones fire a lighter `anomaly.updated` event with the bumped count.

Suppression: when an observation is dismissed, its fingerprint is written to
`dismissed_fingerprints` (TTL 24h by default).  New detections that match a
dismissed fingerprint within the TTL are silently dropped.
"""

from __future__ import annotations

from app.core.constants import (
    Collections, WSTopic,
    NotificationType, NotificationCategory, NotificationSeverity,
)
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from bson import ObjectId
from pymongo import ReturnDocument

from app.core.database import get_database
from app.core.datetime_utils import utc_now
from app.core.events import event_bus
from app.modules.notifications.feed import notify
from app.modules.anomalies.fingerprint import compute_fingerprint
from app.modules.anomalies.schemas import (
    AnomalySeverity,
    AnomalyType,
    LogObservationStatus,
    score_to_severity,
)
from app.modules.incidents.schemas import IncidentInDB, SeverityLevel

# Fallback suppression TTL when no server context is available (seconds).
_DEFAULT_SUPPRESSION_TTL_S: int = int(os.getenv("ANOMALY_SUPPRESSION_TTL_S", "86400"))


def _suppression_ttl_s(server: dict) -> int:
    """Per-server suppression TTL from detection_config, fallback to env/default."""
    cfg = server.get("detection_config") or {}
    hours = cfg.get("anomaly_suppression_ttl_hours", 24.0)
    return max(3600, int(float(hours) * 3600))


def _auto_promote_enabled(server: dict) -> bool:
    """Return True if auto-promote is enabled for this server."""
    cfg = server.get("detection_config") or {}
    # Per-server flag takes precedence; fall back to env var for backwards compat.
    flag = cfg.get("anomaly_auto_promote")
    if flag is not None:
        return bool(flag)
    return bool(os.getenv("ANOMALY_AUTO_PROMOTE"))

# In-process cache of reason weights.  Refreshed every 60s to avoid a DB
# lookup on every flagged log.  Keyed by reason string → weight (0.1–1.0).
_reason_weight_cache: Dict[str, float] = {}
_reason_weight_cache_ts: float = 0.0
_REASON_CACHE_TTL = 60.0  # seconds


async def _get_reason_weights(db) -> Dict[str, float]:
    """Return per-reason weights derived from dismiss/promote feedback.

    weight = max(0.1, promoted / (promoted + dismissed))
    Falls back to 1.0 when fewer than 5 total actions for that reason.
    """
    global _reason_weight_cache, _reason_weight_cache_ts
    now = time.monotonic()
    if now - _reason_weight_cache_ts < _REASON_CACHE_TTL:
        return _reason_weight_cache

    stats = await db[Collections.REASON_STATS].find({}).to_list(length=500)
    weights: Dict[str, float] = {}
    for s in stats:
        p = s.get("promoted_count", 0)
        d = s.get("dismissed_count", 0)
        if p + d >= 5:
            weights[s["reason"]] = max(0.1, p / (p + d))
    _reason_weight_cache = weights
    _reason_weight_cache_ts = now
    return weights


def _apply_weights(flags: List[Tuple[str, int]], weights: Dict[str, float]) -> int:
    """Apply per-reason weights to raw score deltas and return final score (0–10)."""
    total = sum(delta * weights.get(reason, 1.0) for reason, delta in flags)
    return min(10, max(0, round(total)))

_SEVERITY_MAP = {
    AnomalySeverity.LOW: SeverityLevel.LOW,
    AnomalySeverity.MEDIUM: SeverityLevel.MEDIUM,
    AnomalySeverity.HIGH: SeverityLevel.HIGH,
}


def _dedup_window_s(server: dict) -> int:
    """Read per-server dedup window from detection_config, fall back to 2h."""
    cfg = server.get("detection_config") or {}
    hours = cfg.get("anomaly_dedup_window_hours", 2.0)
    return max(60, int(float(hours) * 3600))


class AnomaliesService:

    # ────────────────────────────────────────────────────────────────────
    # Write paths
    # ────────────────────────────────────────────────────────────────────

    async def _is_suppressed(self, db, server_id: str, fingerprint: str) -> bool:
        """Return True if this fingerprint was recently dismissed."""
        doc = await db[Collections.DISMISSED_FINGERPRINTS].find_one(
            {"server_id": server_id, "fingerprint": fingerprint}
        )
        return doc is not None

    async def record_log_observation(
        self,
        log: dict,
        server: dict,
        flags: List[Tuple[str, int]],
    ) -> Optional[str]:
        """
        Upsert a `type=log` observation.  Returns the observation id, or None
        if `flags` is empty or the fingerprint is currently suppressed.
        """
        if not flags:
            return None

        db = get_database()
        server_id = str(server["_id"])
        reasons = [r for r, _ in flags]
        weights = await _get_reason_weights(db)
        score = _apply_weights(flags, weights)
        severity = score_to_severity(score)
        msg = (log.get("message") or "")[:2000]
        fp = compute_fingerprint(server_id, AnomalyType.LOG.value, msg, reasons)

        if await self._is_suppressed(db, server_id, fp):
            return None

        now = utc_now()
        window_start = now - timedelta(seconds=_dedup_window_s(server))

        updated = await db[Collections.LOG_OBSERVATIONS].find_one_and_update(
            {
                "server_id": server_id,
                "fingerprint": fp,
                "status": LogObservationStatus.PENDING_REVIEW.value,
                "last_seen_at": {"$gte": window_start},
            },
            {
                "$inc": {"occurrence_count": 1},
                "$set": {
                    "last_seen_at": now,
                    "last_log_id": str(log["_id"]) if log.get("_id") else None,
                },
                "$push": {
                    "sample_log_ids": {
                        "$each": [str(log["_id"])] if log.get("_id") else [],
                        "$slice": -5,
                    }
                },
                "$max": {"score": score},
            },
            return_document=ReturnDocument.AFTER,
        )

        if updated is not None:
            obs_id = str(updated["_id"])
            _emit_updated(obs_id, server_id, updated.get("occurrence_count", 1))
            await self.maybe_auto_promote(obs_id, server_id)
            return obs_id

        # First occurrence in this window — insert a fresh row
        doc = {
            "server_id": server_id,
            "fingerprint": fp,
            "type": AnomalyType.LOG.value,
            "log_id": str(log.get("_id")) if log.get("_id") else None,
            "last_log_id": str(log.get("_id")) if log.get("_id") else None,
            "log_message": msg,
            "log_timestamp": log.get("timestamp"),
            "sample_log_ids": [str(log["_id"])] if log.get("_id") else [],
            "reasons": reasons,
            "score": score,
            "severity": severity.value,
            "status": LogObservationStatus.PENDING_REVIEW.value,
            "promoted_incident_id": None,
            "occurrence_count": 1,
            "first_seen_at": now,
            "last_seen_at": now,
            "detected_at": now,
            "reviewed_at": None,
        }
        result = await db[Collections.LOG_OBSERVATIONS].insert_one(doc)
        obs_id = str(result.inserted_id)
        await _emit_created(
            obs_id, server_id, severity.value, AnomalyType.LOG.value, reasons,
            log_message=msg, fingerprint=fp,
        )
        return obs_id

    async def record_volume_observation(
        self,
        server: dict,
        current: int,
        baseline: float,
        reason: str,
    ) -> str:
        """
        Upsert a `type=volume` observation.  Multiple spikes within the dedup
        window collapse into one row.
        """
        db = get_database()
        server_id = str(server["_id"])
        score = max(3, min(int(round(current / max(baseline, 1))), 10))
        severity = score_to_severity(score)
        msg = f"Log rate spike: {current} logs/min vs baseline {baseline:.1f}"
        reasons = [reason]
        fp = compute_fingerprint(server_id, AnomalyType.VOLUME.value, "", reasons)

        if await self._is_suppressed(db, server_id, fp):
            return ""

        now = utc_now()
        window_start = now - timedelta(seconds=_dedup_window_s(server))

        updated = await db[Collections.LOG_OBSERVATIONS].find_one_and_update(
            {
                "server_id": server_id,
                "fingerprint": fp,
                "status": LogObservationStatus.PENDING_REVIEW.value,
                "last_seen_at": {"$gte": window_start},
            },
            {
                "$inc": {"occurrence_count": 1},
                "$set": {"last_seen_at": now, "log_message": msg},
                "$max": {"score": score},
            },
            return_document=ReturnDocument.AFTER,
        )

        if updated is not None:
            obs_id = str(updated["_id"])
            _emit_updated(obs_id, server_id, updated.get("occurrence_count", 1))
            return obs_id

        doc = {
            "server_id": server_id,
            "fingerprint": fp,
            "type": AnomalyType.VOLUME.value,
            "log_id": None,
            "last_log_id": None,
            "log_message": msg,
            "log_timestamp": now,
            "sample_log_ids": [],
            "reasons": reasons,
            "score": score,
            "severity": severity.value,
            "status": LogObservationStatus.PENDING_REVIEW.value,
            "promoted_incident_id": None,
            "occurrence_count": 1,
            "first_seen_at": now,
            "last_seen_at": now,
            "detected_at": now,
            "reviewed_at": None,
        }
        result = await db[Collections.LOG_OBSERVATIONS].insert_one(doc)
        obs_id = str(result.inserted_id)
        await _emit_created(
            obs_id, server_id, severity.value, AnomalyType.VOLUME.value, reasons,
            log_message=msg, fingerprint=fp,
        )
        return obs_id

    # ────────────────────────────────────────────────────────────────────
    # Read paths
    # ────────────────────────────────────────────────────────────────────

    def _build_filter(
        self,
        server_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        type_: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        allowed_server_ids=None,
    ) -> dict:
        from datetime import datetime
        from app.core.db_utils import apply_server_scope
        q: dict = {}
        apply_server_scope(q, server_id, allowed_server_ids)
        if status and status != "all":
            q["status"] = status
        if severity and severity != "all":
            q["severity"] = severity
        if type_ and type_ != "all":
            q["type"] = type_
        # Date range — applies on `last_seen_at` (the field the list sorts by).
        # Bad input silently ignored.
        date_range: dict = {}
        if from_date:
            try:
                date_range["$gte"] = datetime.fromisoformat(from_date.replace("Z", "+00:00"))
            except Exception:
                pass
        if to_date:
            try:
                date_range["$lte"] = datetime.fromisoformat(to_date.replace("Z", "+00:00"))
            except Exception:
                pass
        if date_range:
            q["last_seen_at"] = date_range
        return q

    async def list(
        self,
        page: int = 1,
        page_size: int = 25,
        server_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        type_: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        allowed_server_ids=None,
    ):
        db = get_database()
        q = self._build_filter(server_id, status, severity, type_, from_date, to_date, allowed_server_ids=allowed_server_ids)

        total = await db[Collections.LOG_OBSERVATIONS].count_documents(q)
        skip = (page - 1) * page_size

        cursor = (
            db[Collections.LOG_OBSERVATIONS]
            .find(q)
            .sort("last_seen_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        rows = await cursor.to_list(length=page_size)

        sids = list({r["server_id"] for r in rows if r.get("server_id")})
        oids = []
        for sid in sids:
            try:
                oids.append(ObjectId(sid))
            except Exception:
                pass

        host_map: dict = {}
        if oids:
            host_docs = await db[Collections.SERVERS].find(
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

    async def get_by_id(self, observation_id: str) -> Optional[dict]:
        db = get_database()
        try:
            oid = ObjectId(observation_id)
        except Exception:
            return None

        obs = await db[Collections.LOG_OBSERVATIONS].find_one({"_id": oid})
        if not obs:
            return None

        obs["_id"] = str(obs["_id"])
        obs["server_hostname"] = ""
        server_id = obs.get("server_id")
        if server_id:
            try:
                server = await db[Collections.SERVERS].find_one(
                    {"_id": ObjectId(server_id)},
                    {"hostname": 1},
                )
                if server:
                    obs["server_hostname"] = server.get("hostname", "")
            except Exception:
                pass

        return obs

    async def stats(self, allowed_server_ids=None) -> dict:
        db = get_database()
        # RBAC (Phase 20.1): None = admin (all servers); a list restricts the
        # aggregate to the principal's assigned servers so headline counts match
        # the scoped list view (observations store server_id as a str).
        pipeline = []
        if allowed_server_ids is not None:
            pipeline.append({"$match": {"server_id": {"$in": list(allowed_server_ids)}}})
        pipeline.append(
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
        )
        agg = await db[Collections.LOG_OBSERVATIONS].aggregate(pipeline).to_list(length=1)
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

        result = await db[Collections.LOG_OBSERVATIONS].update_one(
            {"_id": oid, "status": LogObservationStatus.PENDING_REVIEW.value},
            {"$set": {
                "status": LogObservationStatus.DISMISSED.value,
                "reviewed_at": utc_now(),
            }},
        )
        if not result.modified_count:
            return False

        obs = await db[Collections.LOG_OBSERVATIONS].find_one({"_id": oid}, {"server_id": 1, "fingerprint": 1, "reasons": 1})
        _sid = obs.get("server_id") if obs else None
        fp = obs.get("fingerprint") if obs else None
        obs_reasons = obs.get("reasons", []) if obs else []

        # B3: Record dismissal feedback for each reason
        global _reason_weight_cache_ts
        for reason in obs_reasons:
            await db[Collections.REASON_STATS].update_one(
                {"reason": reason},
                {"$inc": {"dismissed_count": 1}, "$set": {"last_updated": utc_now()}},
                upsert=True,
            )
        _reason_weight_cache_ts = 0.0  # invalidate cache

        # Write suppression record using this server's configured TTL.
        if _sid and fp:
            now = utc_now()
            # Load detection_config to get the per-server suppression window.
            server_doc: dict = {}
            try:
                server_doc = await db[Collections.SERVERS].find_one(
                    {"_id": ObjectId(_sid)}, {"detection_config": 1}
                ) or {}
            except Exception:
                pass
            expires = now + timedelta(seconds=_suppression_ttl_s(server_doc))
            await db[Collections.DISMISSED_FINGERPRINTS].update_one(
                {"server_id": _sid, "fingerprint": fp},
                {
                    "$set": {
                        "dismissed_at": now,
                        "expires_at": expires,
                        "reasons_at_dismissal": obs.get("reasons", []),
                    }
                },
                upsert=True,
            )

        event_bus.emit(WSTopic.ANOMALIES, "anomaly.updated", {
            "observation_id": observation_id,
            "server_id": _sid,
            "status": LogObservationStatus.DISMISSED.value,
        })
        if _sid:
            event_bus.emit(f"servers.{_sid}.anomalies", "anomaly.updated", {
                "observation_id": observation_id,
                "server_id": _sid,
                "status": LogObservationStatus.DISMISSED.value,
            })
        return True

    async def promote_to_incident(
        self, observation_id: str, auto: bool = False
    ) -> Optional[str]:
        """
        Promote a pending observation to a real incident.  Returns the new
        incident_id.  Pass `auto=True` when called by the auto-promotion path
        so the incident context records it.
        """
        db = get_database()
        try:
            oid = ObjectId(observation_id)
        except Exception:
            return None

        obs = await db[Collections.LOG_OBSERVATIONS].find_one({"_id": oid})
        if not obs or obs.get("status") != LogObservationStatus.PENDING_REVIEW.value:
            return None

        sev = AnomalySeverity(obs.get("severity", "low"))
        incident_severity = _SEVERITY_MAP.get(sev, SeverityLevel.LOW)

        count = obs.get("occurrence_count", 1)
        reasons_str = ", ".join(obs.get("reasons", [])) or "manual promotion"
        description = (
            f"Anomaly promoted ({'auto' if auto else 'manual'}): {reasons_str}"
            + (f" ({count} occurrence{'s' if count != 1 else ''})" if count > 1 else "")
        )

        # B3: Record promotion feedback for each reason
        global _reason_weight_cache_ts
        for reason in obs.get("reasons", []):
            await db[Collections.REASON_STATS].update_one(
                {"reason": reason},
                {"$inc": {"promoted_count": 1}, "$set": {"last_updated": utc_now()}},
                upsert=True,
            )
        _reason_weight_cache_ts = 0.0  # invalidate cache

        incident = IncidentInDB(
            server_id=obs["server_id"],
            rule_id="anomaly:promoted",
            log_id=obs.get("last_log_id") or obs.get("log_id") or "",
            severity=incident_severity,
            description=description,
            context={
                "source": "anomaly",
                "observation_id": observation_id,
                "reasons": obs.get("reasons", []),
                "log_message": (obs.get("log_message") or "")[:500],
                "occurrence_count": count,
                "sample_log_ids": obs.get("sample_log_ids", []),
                "auto_promoted": auto,
            },
        )
        inc_result = await db[Collections.INCIDENTS].insert_one(incident.model_dump())
        incident_id = str(inc_result.inserted_id)
        from bson import ObjectId as _OID
        await db[Collections.SERVERS].update_one(
            {"_id": _OID(obs["server_id"])},
            {"$inc": {"open_incidents_count": 1}},
        )
        event_bus.emit(WSTopic.SERVERS, "server.updated", {"server_id": obs["server_id"]})

        await db[Collections.LOG_OBSERVATIONS].update_one(
            {"_id": oid},
            {"$set": {
                "status": LogObservationStatus.PROMOTED_TO_INCIDENT.value,
                "promoted_incident_id": incident_id,
                "reviewed_at": utc_now(),
            }},
        )

        event_bus.emit(WSTopic.ANOMALIES, "anomaly.updated", {
            "observation_id": observation_id,
            "server_id": obs["server_id"],
            "status": LogObservationStatus.PROMOTED_TO_INCIDENT.value,
            "promoted_incident_id": incident_id,
        })
        event_bus.emit(f"servers.{obs['server_id']}.anomalies", "anomaly.updated", {
            "observation_id": observation_id,
            "server_id": obs["server_id"],
            "status": LogObservationStatus.PROMOTED_TO_INCIDENT.value,
            "promoted_incident_id": incident_id,
        })
        event_bus.emit(WSTopic.INCIDENTS, "incident.created", {
            "incident_id": incident_id,
            "server_id": obs["server_id"],
            "severity": incident_severity.value,
            "rule_name": "Anomaly (promoted)",
            "action_level": 3,
        })
        event_bus.emit(f"servers.{obs['server_id']}.incidents", "incident.created", {
            "incident_id": incident_id,
            "server_id": obs["server_id"],
            "severity": incident_severity.value,
            "rule_name": "Anomaly (promoted)",
            "action_level": 3,
        })
        event_bus.emit(WSTopic.DASHBOARD_SUMMARY, "incident.created", {"incident_id": incident_id})

        return incident_id

    # ────────────────────────────────────────────────────────────────────
    # Auto-promotion (B6)
    # ────────────────────────────────────────────────────────────────────

    async def maybe_auto_promote(
        self, obs_id: str, server_id: str, force: bool = False
    ) -> bool:
        """
        Auto-promote if:
          - severity == high
          - occurrence_count >= 3
          - fingerprint NOT in dismissed_fingerprints
          - env ANOMALY_AUTO_PROMOTE=1  (or force=True for explicit endpoint call)

        Returns True if promoted.
        """
        db = get_database()

        if not force:
            # Load this server's detection_config to check per-server flag.
            server_doc: dict = {}
            try:
                server_doc = await db[Collections.SERVERS].find_one(
                    {"_id": ObjectId(server_id)}, {"detection_config": 1}
                ) or {}
            except Exception:
                pass
            if not _auto_promote_enabled(server_doc):
                return False

        try:
            oid = ObjectId(obs_id)
        except Exception:
            return False

        obs = await db[Collections.LOG_OBSERVATIONS].find_one(
            {"_id": oid, "status": LogObservationStatus.PENDING_REVIEW.value},
            {"severity": 1, "occurrence_count": 1, "fingerprint": 1},
        )
        if not obs:
            return False
        if obs.get("severity") != AnomalySeverity.HIGH.value:
            return False
        if (obs.get("occurrence_count") or 1) < 3:
            return False
        fp = obs.get("fingerprint", "")
        if fp and await self._is_suppressed(db, server_id, fp):
            return False

        incident_id = await self.promote_to_incident(obs_id, auto=True)
        return incident_id is not None


# ────────────────────────────────────────────────────────────────────────
# Private emit helpers
# ────────────────────────────────────────────────────────────────────────

async def _emit_created(
    obs_id: str,
    server_id: str,
    severity: str,
    type_: str,
    reasons: list,
    *,
    log_message: str = "",
    fingerprint: str = "",
):
    payload = {
        "observation_id": obs_id,
        "server_id": server_id,
        "severity": severity,
        "type": type_,
        "reasons": reasons,
    }
    event_bus.emit(WSTopic.ANOMALIES, "anomaly.created", payload)
    event_bus.emit(f"servers.{server_id}.anomalies", "anomaly.created", payload)
    # In-app notification (chosen group). Dedup by fingerprint so a pattern that
    # re-detects after its dedup window doesn't re-spam the feed for a day.
    await notify(
        type=NotificationType.ANOMALY_DETECTED,
        category=NotificationCategory.ANOMALY,
        severity=(
            NotificationSeverity.WARNING
            if severity == AnomalySeverity.HIGH.value
            else NotificationSeverity.INFO
        ),
        title="New anomaly detected",
        body=(log_message or ", ".join(reasons) or "")[:160],
        link=f"/anomalies/{obs_id}",
        server_id=server_id,
        entity_type="anomaly",
        entity_id=obs_id,
        dedup_key=f"anomaly:{server_id}:{fingerprint}" if fingerprint else None,
        dedup_window_s=24 * 3600,
    )


def _emit_updated(obs_id: str, server_id: str, occurrence_count: int):
    payload = {
        "observation_id": obs_id,
        "server_id": server_id,
        "occurrence_count": occurrence_count,
    }
    event_bus.emit(WSTopic.ANOMALIES, "anomaly.updated", payload)
    event_bus.emit(f"servers.{server_id}.anomalies", "anomaly.updated", payload)
