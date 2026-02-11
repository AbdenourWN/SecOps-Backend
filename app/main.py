from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.core.database import connect_to_mongo, close_mongo_connection
from app.modules.servers.router import router as servers_router
from app.modules.logs.router import router as logs_router
from app.modules.automation.router import router as automation_router
from app.core.scheduler import start_scheduler
from app.modules.analysis.service import AnalysisService
from app.modules.metrics.router import router as metrics_router
from app.modules.analysis.router import router as analysis_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup --
    await connect_to_mongo()

    # Seed Rules (One time check)
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

app.include_router(servers_router, prefix="/api/servers", tags=["Servers"])
app.include_router(logs_router, prefix="/api/logs", tags=["Logs"])
app.include_router(automation_router, prefix="/api/automation", tags=["Automation"])
app.include_router(metrics_router, prefix="/api/metrics", tags=["Metrics"])
app.include_router(analysis_router, prefix="/api/analysis", tags=["AI Analysis"])

