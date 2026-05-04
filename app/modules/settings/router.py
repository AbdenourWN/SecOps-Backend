from fastapi import APIRouter
from app.modules.settings.service import SystemSettingsService
from app.modules.settings.schemas import SystemSettingsUpdate

router = APIRouter()


@router.get("/system")
async def get_system_settings():
    return await SystemSettingsService().get_settings()


@router.patch("/system")
async def update_system_settings(data: SystemSettingsUpdate):
    return await SystemSettingsService().update_settings(
        data.model_dump(exclude_none=True)
    )
