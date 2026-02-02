from pydantic import BaseModel, Field, ConfigDict
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
    
    model_config = ConfigDict(populate_by_name=True)

 # What we send back to the user
class ServerResponse(ServerBase):
    id: UUID = Field(alias="_id")

    model_config = ConfigDict(
        populate_by_name=True, # Allows us to use 'id' or '_id'
        from_attributes=True    # Helps Pydantic read data from DB objects
    )