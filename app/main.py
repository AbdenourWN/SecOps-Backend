from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.core.database import connect_to_mongo, close_mongo_connection

# 1. Define the Lifespan (Startup & Shutdown logic)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup --
    await connect_to_mongo()
    yield
    # -- Shutdown --
    await close_mongo_connection()

# 2. Initialize the App
app = FastAPI(
    title="SecOps Backend", 
    version="1.0.0",
    lifespan=lifespan
)

@app.get("/")
async def health_check():
    return {"status": "ok", "message": "SecOps Backend is running"}