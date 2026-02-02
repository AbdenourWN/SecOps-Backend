from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings 


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
        db.client = AsyncIOMotorClient(MONGO_URI, uuidRepresentation="standard")
        # Send a ping to confirm connection
        await db.client.admin.command('ping')
        print(f"✅ Connected to MongoDB: {DB_NAME}")
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