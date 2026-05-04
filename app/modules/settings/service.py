from app.core.database import get_database
from app.core.config import settings

_COLLECTION = "system_settings"
_DOC_ID = "global"


class SystemSettingsService:
    async def get_settings(self) -> dict:
        db = get_database()
        doc = await db[_COLLECTION].find_one({"_id": _DOC_ID})
        stored = doc.get("max_concurrent_servers") if doc else None
        return {
            "max_concurrent_servers": stored if stored is not None else settings.MAX_CONCURRENT_SERVERS,
            "env_default": settings.MAX_CONCURRENT_SERVERS,
        }

    async def update_settings(self, data: dict) -> dict:
        from app.core.scheduler import set_concurrent_limit

        db = get_database()
        update = {k: v for k, v in data.items() if v is not None}
        if not update:
            return await self.get_settings()

        await db[_COLLECTION].update_one(
            {"_id": _DOC_ID},
            {"$set": update},
            upsert=True,
        )

        if "max_concurrent_servers" in update:
            set_concurrent_limit(update["max_concurrent_servers"])

        return await self.get_settings()


async def load_system_settings() -> None:
    """Apply any DB-stored overrides on startup (called after MongoDB connects)."""
    from app.core.scheduler import set_concurrent_limit

    db = get_database()
    doc = await db[_COLLECTION].find_one({"_id": _DOC_ID})
    if doc and doc.get("max_concurrent_servers") is not None:
        set_concurrent_limit(doc["max_concurrent_servers"])
        print(f"⚙️  System settings loaded — max_concurrent_servers={doc['max_concurrent_servers']}")
