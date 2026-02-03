from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.core.database import connect_to_mongo, close_mongo_connection
from app.modules.servers.router import router as servers_router
import asyncio
from app.modules.servers.service import ServerService


async def run_health_monitor():
    """
    Runs continuously in the background.
    """
    service = ServerService()
    while False:
        # 1. Wait a bit for DB to connect on startup
        await asyncio.sleep(5)

        try:
            # 2. Run the logic
            await service.update_all_server_statuses()
        except Exception as e:
            print(f"❌ Health Monitor Error: {e}")

        # 3. Wait 30 seconds before next scan
        await asyncio.sleep(30)


# 1. Define the Lifespan (Startup & Shutdown logic)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup --
    await connect_to_mongo()

    asyncio.create_task(run_health_monitor())

    yield
    # -- Shutdown --
    await close_mongo_connection()


# 2. Initialize the App
app = FastAPI(title="SecOps Backend", version="1.0.0", lifespan=lifespan)


@app.get("/")
async def health_check():
    return {"status": "ok", "message": "SecOps Backend is running"}


app.include_router(servers_router, prefix="/api/servers", tags=["Servers"])
