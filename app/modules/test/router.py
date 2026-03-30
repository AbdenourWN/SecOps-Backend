from fastapi import APIRouter, Query
from typing import Optional
from app.modules.test.service import SimulationService

router = APIRouter()
service = SimulationService()


@router.get("/scenarios")
async def list_scenarios():
    """
    Lists all available fake log scenarios and which rules they trigger.
    """
    return await service.get_scenarios()


@router.post("/simulate")
async def simulate_system_logs(
    server_id: Optional[str] = Query(None, description="Target a specific server (or all if empty)"),
    scenario: Optional[str] = Query(None, description="Run a specific scenario (or all if empty)"),
):
    """
    Step 1: SSHes into servers and writes fake log entries into the system journal.
    Linux: uses `logger` command → picked up by `journalctl`
    Windows: uses `Write-EventLog` → picked up by `Get-WinEvent`

    Wait ~60s for the scheduler to collect and analyze them.
    """
    return await service.simulate_system_logs(server_id=server_id, scenario=scenario)


@router.post("/simulate/file-logs")
async def simulate_file_logs(
    server_id: Optional[str] = Query(None, description="Target a specific server (or all if empty)"),
):
    """
    Step 2 & 3: Creates test log files on servers, writes fake application logs,
    and auto-registers logSources. The FileWatcher picks them up on the next cycle.
    """
    return await service.simulate_file_logs(server_id=server_id)
