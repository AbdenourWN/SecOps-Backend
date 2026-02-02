from fastapi import APIRouter
from pydantic import BaseModel
from app.modules.servers.service import ServerService
from app.modules.servers.schemas import ServerCreate, ServerResponse
from typing import List
from uuid import UUID
from fastapi import APIRouter, HTTPException
from app.modules.servers.schemas import ServerCreate, ServerResponse

router = APIRouter()
service = ServerService()

# This defines the data we expect from the user
class CommandRequest(BaseModel):
    ip: str
    username: str
    password: str
    command: str = "uptime"  # Default command


# 1. List All Servers
@router.get("/", response_model=List[ServerResponse])
async def list_servers():
    return await service.get_all_servers()

# 2. Get One Server
@router.get("/{server_id}", response_model=ServerResponse)
async def get_server_details(server_id: UUID):
    server = await service.get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return server

# 3. Execute Command using ID (The Smart One)
class IDCommandRequest(BaseModel):
    command: str = "uptime"

@router.post("/{server_id}/execute")
async def execute_on_server(server_id: UUID, request: IDCommandRequest):
    result = await service.execute_command_by_id(server_id, request.command)
    if result.get("status") == "failed":
         # If server not found, 404. If SSH failed, 400.
        if result.get("error") == "Server not found":
            raise HTTPException(status_code=404, detail="Server not found")
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@router.post("/execute")
async def execute_command(request: CommandRequest):
    result = await service.run_command(
        request.ip, 
        request.username, 
        request.password, 
        request.command
    )
    return result
@router.post("/", response_model=dict)
async def add_server_to_db(server: ServerCreate):
    result = await service.create_server(server)
    return result