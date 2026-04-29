import logging
import traceback
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from app.core.database import connect_to_mongo, close_mongo_connection
from app.core.elasticsearch import connect_to_elasticsearch, close_elasticsearch
from app.modules.servers.router import router as servers_router
from app.modules.logs.router import router as logs_router
from app.modules.automation.router import router as automation_router
from app.core.scheduler import start_scheduler
from app.modules.metrics.router import router as metrics_router
from app.modules.analysis.router import router as analysis_router
from app.modules.incidents.router import router as incidents_router
from app.modules.dashboard.router import router as dashboard_router
from app.modules.test.router import router as test_router
from app.modules.notifications.router import router as notifications_router
from app.modules.anomalies.router import router as anomalies_router
from app.modules.ws.router import router as ws_router
from app.modules.ws.terminal_router import router as terminal_ws_router
from app.core.connection_pool import connection_pool
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings


async def _ensure_indexes():
    """
    Create all MongoDB indexes on startup. `create_index` is idempotent —
    safe to re-run on every boot; no-ops when the index already exists.
    """
    from app.core.database import get_database
    db = get_database()

    # ── log_observations (Tier 2 anomaly) ────────────────────────────────────
    # List page (newest first per server) + pending queue + 30-day TTL
    await db["log_observations"].create_index([("server_id", 1), ("detected_at", -1)])
    await db["log_observations"].create_index([("status", 1), ("detected_at", -1)])
    await db["log_observations"].create_index(
        "detected_at", expireAfterSeconds=30 * 24 * 3600
    )

    # ── server_log_patterns (Tier 2 novel-pattern dedup) ─────────────────────
    await db["server_log_patterns"].create_index(
        [("server_id", 1), ("pattern_hash", 1)], unique=True
    )
    await db["server_log_patterns"].create_index([("server_id", 1), ("first_seen_at", 1)])

    # ── incidents ─────────────────────────────────────────────────────────────
    # Dedup lookup: runs on every log line in analyze_logs() — most critical index.
    # Filter: server_id + rule_id + status $in [open, verifying] + detected_at range.
    await db["incidents"].create_index(
        [("server_id", 1), ("rule_id", 1), ("status", 1), ("detected_at", -1)],
        name="idx_incidents_dedup",
    )
    # Verify-remediation sweep: runs every 60s in job_verify_remediation.
    # Filter: status == "verifying" AND verification_until < now.
    await db["incidents"].create_index(
        [("status", 1), ("verification_until", 1)],
        name="idx_incidents_verify",
    )

    # ── rules ─────────────────────────────────────────────────────────────────
    # Rule cache refresh: loads all enabled rules every 5 min.
    await db["rules"].create_index([("enabled", 1)], name="idx_rules_enabled")

    # ── log_sources ───────────────────────────────────────────────────────────
    # Active-sources list: fetched every 60s by job_file_watcher.
    await db["log_sources"].create_index([("is_active", 1)], name="idx_log_sources_active")
    # Per-server lookup: used by get_sources_by_server.
    await db["log_sources"].create_index([("server_id", 1)], name="idx_log_sources_server")

    print("✅ Indexes ensured (incidents, rules, log_sources, log_observations, server_log_patterns)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup --
    await connect_to_mongo()
    await connect_to_elasticsearch()

    # Seeding is manual only — run `python seed.py` to populate defaults.
    # Start connection pool idle sweeper
    await connection_pool.start()

    # All MongoDB indexes (idempotent — safe to re-run on every boot)
    await _ensure_indexes()

    # Start the scheduler (health, telemetry, file_watcher jobs)
    start_scheduler()

    yield

    # -- Shutdown --
    await connection_pool.close_all(grace_s=5)
    await close_elasticsearch()
    await close_mongo_connection()

app = FastAPI(title="SecOps Backend", version="1.0.0", lifespan=lifespan)

@app.get("/")
async def health_check():
    return {"status": "ok", "message": "SecOps Backend is running"}

_logger = logging.getLogger("secops.unhandled")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    correlation_id = str(uuid.uuid4())[:8]
    _logger.error(
        "Unhandled error [%s] %s %s — %s\n%s",
        correlation_id,
        request.method,
        request.url.path,
        exc,
        traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "An unexpected error occurred.",
            "correlation_id": correlation_id,
        },
    )



app.include_router(servers_router, prefix="/api/servers", tags=["Servers"])
app.include_router(logs_router, prefix="/api/logs", tags=["Logs"])
app.include_router(automation_router, prefix="/api/automation", tags=["Automation"])
app.include_router(metrics_router, prefix="/api/metrics", tags=["Metrics"])
app.include_router(analysis_router, prefix="/api/analysis", tags=["AI Analysis"])
app.include_router(incidents_router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(test_router, prefix="/api/test", tags=["Test & Simulation"])
app.include_router(notifications_router, prefix="/api/notifications", tags=["Notifications"])
app.include_router(anomalies_router, prefix="/api/anomalies", tags=["Anomalies"])
app.include_router(ws_router, prefix="/api", tags=["WebSocket"])
app.include_router(terminal_ws_router, prefix="/api", tags=["Terminal WebSocket"])



app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS.split(",") if settings.ALLOWED_ORIGINS != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

