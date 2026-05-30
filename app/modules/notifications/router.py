from fastapi import APIRouter, HTTPException
from app.modules.notifications.service import NotificationService
from app.modules.notifications.schemas import NotificationConfigCreate, LlmConfigUpdate

router = APIRouter()


@router.get("/config")
async def get_notification_configs():
    """Returns all notification configurations."""
    service = NotificationService()
    return await service.get_configs()


@router.post("/config")
async def save_notification_config(config: NotificationConfigCreate):
    """
    Create or update a notification config.
    If a config for the same channel exists, it will be updated.
    """
    service = NotificationService()
    return await service.save_config(config.model_dump())


@router.delete("/config/{channel}")
async def delete_notification_config(channel: str):
    """Deletes a notification config by channel name."""
    service = NotificationService()
    return await service.delete_config(channel)


@router.post("/test")
async def send_test_alert():
    """
    Sends a test alert to verify the notification pipeline.
    Uses whatever config is currently active.
    """
    service = NotificationService()
    return await service.test_alert()


@router.get("/llm")
async def get_llm_config():
    """Returns the active LLM provider/model + the .env defaults."""
    service = NotificationService()
    return await service.get_llm_config()


@router.put("/llm")
async def update_llm_config(config: LlmConfigUpdate):
    """
    Override the LLM provider/model at runtime. Persisted in `settings` and
    applied live (clears the get_chat_model cache) — no restart needed.
    """
    service = NotificationService()
    try:
        return await service.save_llm_config(config.provider, config.model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
