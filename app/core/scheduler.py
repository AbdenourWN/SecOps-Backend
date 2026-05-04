import asyncio
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from bson import ObjectId

from app.core.config import settings
from app.core.database import get_database
from app.core.events import event_bus
from app.modules.anomalies.service import AnomaliesService
from app.modules.heuristics.service import HeuristicService
from app.modules.logs.file_watcher import FileWatcherService
from app.modules.logs.service import LogService
from app.modules.metrics.service import MetricService
from app.modules.servers.service import ServerService

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

# Global semaphore: cap how many servers run collection in parallel.
# Per-server serialization is handled by connection_pool's per-entry lock.
# `_concurrent_limit` is mutable — call set_concurrent_limit() to update at runtime.
_concurrent_limit: int = settings.MAX_CONCURRENT_SERVERS
_semaphore = asyncio.Semaphore(_concurrent_limit)


def get_concurrent_limit() -> int:
    return _concurrent_limit


def set_concurrent_limit(n: int) -> None:
    global _semaphore, _concurrent_limit
    _concurrent_limit = n
    _semaphore = asyncio.Semaphore(n)
    logger.info("scheduler concurrent limit updated to %d", n)


# Expose lock accessor for code that still imports it (e.g. health-check path in ServerService).
# Health check creates a fresh executor (no pool), so it doesn't share the pool lock.
_server_locks: dict[str, asyncio.Lock] = {}


def _get_server_lock(server_id: str) -> asyncio.Lock:
    if server_id not in _server_locks:
        _server_locks[server_id] = asyncio.Lock()
    return _server_locks[server_id]


async def _with_semaphore(coro):
    async with _semaphore:
        return await coro


# ---------------------------------------------------------------------------
# Job: health check — stays fast + independent (TCP only, no pool)
# ---------------------------------------------------------------------------

async def job_health_check():
    try:
        service = ServerService()
        t0 = asyncio.get_event_loop().time()
        await service.update_all_server_statuses()
        elapsed = asyncio.get_event_loop().time() - t0
        logger.info("health_check complete in %.1fs", elapsed)
    except Exception as e:
        logger.error("health_check failed: %s", e)


# ---------------------------------------------------------------------------
# Job: combined telemetry — logs + metrics in one SSH/WinRM session per server
# ---------------------------------------------------------------------------

_metric_service = MetricService()
_log_service = LogService()
_heuristic_service = HeuristicService()
_anomalies_service = AnomaliesService()


async def _collect_telemetry_for_server(server: dict):
    from app.core.connection_pool import connection_pool, _STALL_THRESHOLD

    server_id = str(server["_id"])
    hostname = server.get("hostname", server_id)

    async with connection_pool.try_get(server_id, timeout=5) as executor:
        if executor is None:
            skip_count = connection_pool.get_skip_count(server_id)
            logger.warning("[scheduler] skipped collection for %s (terminal busy, consecutive=%d)",
                           hostname, skip_count)
            event_bus.emit("servers", "collection_skipped", {
                "server_id": server_id,
                "hostname": hostname,
                "consecutive": skip_count,
                "reason": "terminal_busy",
            })
            if skip_count >= _STALL_THRESHOLD:
                logger.warning("[scheduler] telemetry STALLED for %s (%d consecutive skips)",
                               hostname, skip_count)
                event_bus.emit("servers", "collection_stalled", {
                    "server_id": server_id,
                    "hostname": hostname,
                    "consecutive": skip_count,
                })
            return

        # Sequential — NOT asyncio.gather. Both use the same WinRM Protocol
        # object under the hood; concurrent open_shell() calls on the same
        # requests.Session trigger NTLM MIC failures on Windows.
        for label, coro in (
            ("metrics", _metric_service.collect_with(executor, server)),
            ("logs",    _log_service.collect_logs_with(executor, server)),
        ):
            try:
                await coro
            except Exception as e:
                logger.error("[scheduler] %s collection error for %s: %s", label, hostname, e)

    # Volume-spike check runs after collection (and outside the pool lock —
    # it's a single ES count + Mongo update, doesn't need the executor).
    # Re-fetch the server doc so we get the freshly-updated baseline for the
    # NEXT call rather than racing with a stale one.
    try:
        from app.core.database import get_database
        from bson import ObjectId
        db = get_database()
        fresh_server = await db["servers"].find_one({"_id": ObjectId(server_id)})
        if fresh_server is not None:
            spike = await _heuristic_service.check_volume_spike(fresh_server)
            if spike is not None:
                current, baseline, reason = spike
                await _anomalies_service.record_volume_observation(
                    server=fresh_server,
                    current=current,
                    baseline=baseline,
                    reason=reason,
                )
                logger.info("[scheduler] volume spike on %s: %s", hostname, reason)
    except Exception as e:
        logger.error("[scheduler] volume spike check failed for %s: %s", hostname, e)


async def job_collect_telemetry():
    try:
        db = get_database()
        servers = await db["servers"].find().to_list(length=10000)
        if not servers:
            return

        # Skip servers that are offline — avoids hanging on dead hosts.
        # Health check still runs for all and will flip is_online when they recover.
        online = [s for s in servers if s.get("is_online", True)]
        skipped_count = len(servers) - len(online)

        t0 = asyncio.get_event_loop().time()
        logger.info("[scheduler] telemetry: %d servers (%d offline-skipped)", len(online), skipped_count)

        tasks = [_with_semaphore(_collect_telemetry_for_server(s)) for s in online]
        await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = asyncio.get_event_loop().time() - t0
        logger.info("[scheduler] telemetry complete in %.1fs", elapsed)

        # One event per tick so the frontend refreshes last_metrics on all server cards.
        event_bus.emit("servers", "servers.metrics_updated", {"count": len(online)})

    except Exception as e:
        logger.error("job_collect_telemetry failed: %s", e)


# ---------------------------------------------------------------------------
# Job: verify remediation — auto-resolve VERIFYING incidents whose window expired
# ---------------------------------------------------------------------------

async def job_verify_remediation():
    """
    For every incident in `verifying` state whose `verification_until` is in the past,
    promote to `resolved` (auto). If the underlying problem had recurred, the analysis
    service would have flipped it back to verifying with an incremented attempt count
    or escalated it; reaching this point means the rule didn't fire again — the fix
    held.
    """
    try:
        db = get_database()
        now = datetime.now(timezone.utc)
        cursor = db["incidents"].find({
            "status": "verifying",
            "verification_until": {"$lt": now},
        })
        to_resolve = await cursor.to_list(length=500)
        if not to_resolve:
            return

        for inc in to_resolve:
            await db["incidents"].update_one(
                {"_id": inc["_id"]},
                {"$set": {
                    "status": "resolved",
                    "auto_resolved_at": now,
                    "resolved_at": now,
                    "description": inc.get("description", "") + " (Auto-Resolved)",
                }},
            )
            _sid = inc.get("server_id")
            if _sid:
                await db["servers"].update_one(
                    {"_id": ObjectId(_sid)},
                    {"$inc": {"open_incidents_count": -1}},
                )
                event_bus.emit("servers", "server.updated", {"server_id": _sid})
            event_bus.emit("incidents", "incident.resolved", {
                "incident_id": str(inc["_id"]),
                "server_id": _sid,
                "auto": True,
            })
            if _sid:
                event_bus.emit(f"servers.{_sid}.incidents", "incident.resolved", {  # deprecated: remove when RBAC lands
                    "incident_id": str(inc["_id"]),
                    "server_id": _sid,
                    "auto": True,
                })
            event_bus.emit("dashboard.summary", "incident.resolved", {
                "incident_id": str(inc["_id"]),
            })

        logger.info("[scheduler] auto-resolved %d verified incident(s)", len(to_resolve))

    except Exception as e:
        logger.error("job_verify_remediation failed: %s", e)


# ---------------------------------------------------------------------------
# Job: file watcher — kept separate (per-source iteration, uses pool internally)
# ---------------------------------------------------------------------------

async def job_file_watcher():
    try:
        db = get_database()
        service = FileWatcherService()
        sources = await service.get_all_sources()
        if not sources:
            return

        # Same online-only policy as job_collect_telemetry — file-watcher
        # commands run through the connection pool and would hang on dead
        # hosts. Health check still flips servers back ONLINE on recovery.
        online_ids = {
            str(s["_id"])
            for s in await db["servers"]
            .find({"is_online": True}, {"_id": 1})
            .to_list(length=10000)
        }
        active = [s for s in sources if str(s.get("server_id")) in online_ids]
        skipped = len(sources) - len(active)

        if not active:
            logger.info("[scheduler] file_watcher: 0 active sources (%d offline-skipped)", skipped)
            return

        t0 = asyncio.get_event_loop().time()
        logger.info("[scheduler] file_watcher: %d sources (%d offline-skipped)", len(active), skipped)

        tasks = [
            _with_semaphore(service.process_file_source(source))
            for source in active
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = asyncio.get_event_loop().time() - t0
        logger.info("[scheduler] file_watcher complete in %.1fs", elapsed)

    except Exception as e:
        logger.error("job_file_watcher failed: %s", e)


# ---------------------------------------------------------------------------
# Scheduler startup
# ---------------------------------------------------------------------------

def start_scheduler():
    from datetime import timedelta

    # APScheduler job options applied to every job:
    #   max_instances=1  — only one tick of a given job runs at a time
    #   coalesce=True    — if N ticks were missed, run once (not N times)
    #   misfire_grace_time=30 — forgive ticks that fire up to 30s late
    _job_kwargs = dict(max_instances=1, coalesce=True, misfire_grace_time=30)

    def _at(offset_s: int):
        return datetime.now(timezone.utc) + timedelta(seconds=offset_s)

    scheduler.add_job(
        job_health_check, "interval", seconds=60,
        next_run_time=_at(0), **_job_kwargs,
    )
    scheduler.add_job(
        job_collect_telemetry, "interval", seconds=60,
        next_run_time=_at(15), **_job_kwargs,
    )
    scheduler.add_job(
        job_file_watcher, "interval", seconds=60,
        next_run_time=_at(45), **_job_kwargs,
    )
    # Auto-resolve VERIFYING incidents whose verification window has elapsed
    # without the rule re-firing. Runs every 60 s, offset to land between the
    # other jobs.
    scheduler.add_job(
        job_verify_remediation, "interval", seconds=60,
        next_run_time=_at(30), **_job_kwargs,
    )

    scheduler.start()
    logger.info(
        "scheduler started (max_concurrent=%d, coalesce=True, staggered offsets 0/15/30/45s)",
        _concurrent_limit,
    )
    print(f"⏰ Scheduler started — health@+0s, telemetry@+15s, verify@+30s, file_watcher@+45s "
          f"(max {_concurrent_limit} concurrent)")
