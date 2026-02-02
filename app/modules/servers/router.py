from fastapi import APIRouter
from pydantic import BaseModel
from app.modules.servers.service import ServerService
from app.modules.servers.schemas import ServerCreate, ServerResponse

router = APIRouter()
service = ServerService()

# This defines the data we expect from the user
class CommandRequest(BaseModel):
    ip: str
    username: str
    password: str
    command: str = "uptime"  # Default command

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