from fastapi import APIRouter, Query
from typing import Optional
from app.modules.test.service import SimulationService

router = APIRouter()
service = SimulationService()


@router.get("/scenarios")
async def list_scenarios():
    """
    Lists all available fake log scenarios and which rules they trigger.
    Also lists the supported file-log parser types.
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
    parser_type: str = Query(
        "nginx",
        description=(
            "Log format to simulate: nginx | apache | json | raw | all. "
            "The log file is written in the matching format and the LogSource is registered "
            "with the same parser_type so the FileWatcher uses the correct timestamp parser."
        ),
    ),
):
    """
    Step 2 & 3: Writes fake application logs to a test file on each server
    and auto-registers a LogSource with the correct parser_type.

    Each parser type produces differently-formatted lines with real past timestamps:
    - **nginx** / **apache**: combined log format `[DD/Mon/YYYY:HH:MM:SS +0000]`
    - **json**: structured `{"timestamp":"...","level":"...","message":"..."}`
    - **raw**: syslog prefix `MMM DD HH:MM:SS hostname process[pid]: message`
    - **all**: runs all four types, creating one file + LogSource per parser

    The FileWatcher picks them up on the next cycle (~60s) and extracts the
    real event timestamps rather than stamping the ingestion time.
    """
    return await service.simulate_file_logs(server_id=server_id, parser_type=parser_type)
