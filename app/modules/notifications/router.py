from fastapi import APIRouter
from app.modules.notifications.service import NotificationService
from app.modules.notifications.schemas import NotificationConfigCreate

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
