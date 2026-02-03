from pydantic import BaseModel, Field, BeforeValidator, ConfigDict
from typing import Optional, Annotated
from enum import Enum
from datetime import datetime ,timezone

# --- Helpers ---
# This tells Pydantic: "If you see an ObjectId, turn it into a string"
PyObjectId = Annotated[str, BeforeValidator(str)]

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --- Shared Logic ---
class TimestampModel(BaseModel):
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class OSType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"

class ServerStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"
    WARNING = "warning"

class CredentialType(str, Enum):
    PASSWORD = "password"
    SSH_KEY = "ssh_key"

# --- Credential Schemas ---
class CredentialInput(BaseModel):
    username: str
    type: CredentialType = CredentialType.PASSWORD
    secret: str 
    passphrase: Optional[str] = None

class CredentialInDB(TimestampModel):
    username: str
    type: CredentialType
    encrypted_secret: str
    encrypted_passphrase: Optional[str] = None

    class Config:
        populate_by_name = True

class CredentialUpdate(BaseModel):
    username: Optional[str] = None
    type: Optional[CredentialType] = None
    secret: Optional[str] = None 
    passphrase: Optional[str] = None


# --- Server Schemas ---
class ServerBase(BaseModel):
    hostname: str
    ip_address: str
    os_type: OSType = OSType.LINUX

class ServerCreate(ServerBase):
    credential: CredentialInput

class ServerInDB(TimestampModel, ServerBase):
    credential_id: str 

    status: ServerStatus = ServerStatus.UNKNOWN
    last_health_check: Optional[datetime] = None
    
    class Config:
        populate_by_name = True

class ServerResponse(TimestampModel, ServerBase):
    id: PyObjectId = Field(alias="_id")

    status: ServerStatus = ServerStatus.UNKNOWN
    last_health_check: Optional[datetime] = None
    
    class Config:
        populate_by_name = True

class ServerUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_type: Optional[OSType] = None
    
    # Allow updating the stored credential (e.g., changing the password)
    credential: Optional[CredentialUpdate] = None 

    # --- Security Challenge (REQUIRED) ---
    # The user MUST provide the CURRENT password/key to authorize the change
    current_secret: str 

# 3. Delete Request Schema
class ServerDelete(BaseModel):
    # The user MUST provide the CURRENT password/key to authorize deletion
    current_secret: str