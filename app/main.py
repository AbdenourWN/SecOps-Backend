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
from app.modules.ws.router import router as ws_router
from app.modules.ws.terminal_router import router as terminal_ws_router
from app.core.connection_pool import connection_pool
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup --
    await connect_to_mongo()
    await connect_to_elasticsearch()

    # Seeding is manual only — run `python seed.py` to populate defaults.
    # Start connection pool idle sweeper
    await connection_pool.start()

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

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"🔥 UNHANDLED ERROR: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal Server Error", "detail": str(exc)},
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
app.include_router(ws_router, prefix="/api", tags=["WebSocket"])
app.include_router(terminal_ws_router, prefix="/api", tags=["Terminal WebSocket"])



app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS.split(",") if settings.ALLOWED_ORIGINS != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

