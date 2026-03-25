from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from app.core.database import connect_to_mongo, close_mongo_connection
from app.modules.servers.router import router as servers_router
from app.modules.logs.router import router as logs_router
from app.modules.automation.router import router as automation_router
from app.core.scheduler import start_scheduler
from app.modules.analysis.service import AnalysisService
from app.modules.automation.service import AutomationService
from app.modules.metrics.router import router as metrics_router
from app.modules.analysis.router import router as analysis_router
from app.modules.incidents.router import router as incidents_router
from app.modules.dashboard.router import router as dashboard_router
from fastapi.middleware.cors import CORSMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup --
    await connect_to_mongo()

    # Seed Data (One time check — scripts first, then rules link to them)
    await AutomationService().seed_default_scripts()
    await AnalysisService().seed_default_rules()
    
    # Start the "Heartbeat" of the application
    
    start_scheduler()

    yield
    # -- Shutdown --
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



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace "*" with ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],  # Allow GET, POST, DELETE, etc.
    allow_headers=["*"],  # Allow Auth headers
)

