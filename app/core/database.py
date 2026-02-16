from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings 
from pymongo import ASCENDING, DESCENDING



# 2. Get the connection string
MONGO_URI = settings.MONGO_URI
DB_NAME = settings.DB_NAME

# 3. Create the Client (But don't connect yet)
class Database:
    client: AsyncIOMotorClient = None

db = Database()

async def connect_to_mongo():
    """
    Connects to MongoDB when the API starts.
    """
    try:
        # Create a CodecOptions object to specify how to handle UUIDs
        db.client = AsyncIOMotorClient(MONGO_URI)
        # Send a ping to confirm connection
        await db.client.admin.command('ping')
        print(f"✅ Connected to MongoDB: {DB_NAME}")

         # --- PERFORMANCE OPTIMIZATION: CREATE INDEXES ---
        database = db.client[DB_NAME]
        
        # 1. Servers: Ensure IPs are unique so we don't add the same server twice
        await database["servers"].create_index([("ip_address", ASCENDING)], unique=True)
        
        # 2. Logs: We query by Server ID and sort by Timestamp often
        # Compound Index: Finds server first, then sorts by time. Extremely fast.
        await database["logs"].create_index([
            ("server_id", ASCENDING), 
            ("timestamp", DESCENDING)
        ])
        
        # 3. Metrics: Same as logs, we need history for charts
        await database["metrics"].create_index([
            ("server_id", ASCENDING), 
            ("timestamp", DESCENDING)
        ])
        
        print("⚡ Database Indexes Created")

    except Exception as e:
        print(f"❌ Could not connect to MongoDB: {e}")
        raise e

async def close_mongo_connection():
    """
    Closes the connection when the API stops.
    """
    if db.client:
        db.client.close()
        print("🛑 MongoDB connection closed.")

def get_database():
    """
    Returns the database instance to other parts of the app.
    """
    return db.client[DB_NAME]