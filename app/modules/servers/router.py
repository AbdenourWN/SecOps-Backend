import unicodedata
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field, field_validator
from app.modules.servers.service import ServerService
from app.modules.servers.schemas import ServerCreate, ServerResponse, ServerUpdate, ServerDelete, ServerStatus, OSType
from typing import List, Optional
from fastapi import APIRouter, HTTPException


router = APIRouter()
service = ServerService()


_MAX_COMMAND_BYTES = 4096


class IDCommandRequest(BaseModel):
    command: str = Field(default="uptime")
    confirmed: bool = False
    timeout_s: Optional[int] = Field(default=None, ge=1, le=300)

    @field_validator("command")
    @classmethod
    def _hygiene(cls, v: str) -> str:
        v = unicodedata.normalize("NFC", v).strip()
        if not v:
            raise ValueError("Command cannot be empty.")
        if "\x00" in v:
            raise ValueError("Null byte in command is not allowed.")
        # Allow tab and newline; reject other control chars.
        for ch in v:
            if ch < " " and ch not in ("\t", "\n", "\r"):
                raise ValueError("Disallowed control character in command.")
        if len(v.encode("utf-8")) > _MAX_COMMAND_BYTES:
            raise ValueError(f"Command exceeds {_MAX_COMMAND_BYTES} bytes.")
        return v


class ServerListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[ServerResponse]


# 1. List All Servers
@router.get("/", response_model=ServerListResponse)
async def list_servers(
    status: Optional[ServerStatus] = Query(None, description="Filter by status"),
    os_type: Optional[OSType] = Query(None, description="Filter by OS type"),
    search: Optional[str] = Query(None, description="Search hostname or IP address"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(9, ge=1, le=100, description="Items per page"),
):
    return await service.get_all_servers(
        status=status, os_type=os_type, search=search,
        page=page, page_size=page_size,
    )

# 2. Get One Server
@router.get("/{server_id}", response_model=ServerResponse)
async def get_server_details(server_id: str):
    server = await service.get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return server

# 3. Execute Command using ID (The Smart One)

@router.post("/{server_id}/execute")
async def execute_on_server(
    server_id: str,
    request: IDCommandRequest,
    http_request: Request,
):
    source_ip = http_request.client.host if http_request.client else None

    result = await service.execute_command_by_id(
        server_id,
        request.command,
        confirmed=request.confirmed,
        timeout_s=request.timeout_s,
        principal_id=None,  # P4: wire JWT user_id here
        source_ip=source_ip,
    )

    status = result.get("status")

    if status == "blocked":
        raise HTTPException(
            status_code=403,
            detail={"blocked_reason": result.get("blocked_reason"),
                    "error": result.get("error")},
        )

    if status == "requires_confirmation":
        raise HTTPException(
            status_code=412,
            detail={"requires_confirmation": True,
                    "blocked_reason": result.get("blocked_reason"),
                    "error": result.get("error")},
        )

    if status == "rate_limited":
        raise HTTPException(
            status_code=429,
            detail={"retry_after_seconds": result.get("retry_after_seconds"),
                    "error": result.get("error")},
        )

    if status == "failed":
        if result.get("error") == "Server not found":
            raise HTTPException(status_code=404, detail="Server not found")
        raise HTTPException(status_code=400, detail=result.get("error"))

    # success / error / timeout all return 200 with a status field
    return result


# 4. Add New Server (OnBoarding)
@router.post("/", response_model=dict)
async def add_server_to_db(server: ServerCreate):
    result = await service.create_server(server)
    if result.get("status") == "failed":
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


# 5. Update Server
@router.put("/{server_id}")
async def update_server(server_id: str, update_data: ServerUpdate):
    result = await service.update_server(server_id, update_data)
    
    if result.get("status") == "failed":
        if "Authentication Failed" in result.get("error", ""):
            raise HTTPException(status_code=403, detail=result["error"])
        raise HTTPException(status_code=400, detail=result["error"])
        
    return result

# 6. Delete Server
@router.delete("/{server_id}")
async def delete_server(server_id: str, delete_data: ServerDelete):
    """
    Deletes a server. Requires the 'current_secret' in the body for verification.
    """
    result = await service.delete_server(server_id, delete_data)
    
    if result.get("status") == "failed":
        if "Authentication Failed" in result.get("error", ""):
            raise HTTPException(status_code=403, detail=result["error"])
        raise HTTPException(status_code=404, detail="Server not found or other error")
        
    return result