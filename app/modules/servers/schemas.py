from pydantic import BaseModel, Field
from typing import Optional
from uuid import UUID, uuid4

class ServerBase(BaseModel):
    hostname: str
    ip_address: str
    os_type: str = "Linux"  # Default value
    username: str

# What the user sends to us
class ServerCreate(ServerBase):
    password: str  # We need the password to add the server

# What we store in MongoDB
class ServerInDB(ServerBase):
    id: UUID = Field(default_factory=uuid4, alias="_id")
    encrypted_password: str  # In the DB, the password must be encrypted
    class Config:
        # This allows us to use the field name "id" even though it's stored as "_id"
        populate_by_name = True

 # What we send back to the user
class ServerResponse(ServerBase):
    id: UUID