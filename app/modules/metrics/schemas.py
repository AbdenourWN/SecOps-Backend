from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from app.core.datetime_utils import utc_now

class SystemMetric(BaseModel):
    server_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    
    cpu_usage: float = Field(..., description="CPU Load percentage (0-100)")
    ram_usage: float = Field(..., description="RAM Usage percentage (0-100)")
    disk_usage: float = Field(..., description="Root partition usage percentage (0-100)")
    
    # Optional: Raw output for debugging
    raw_data: Optional[str] = None

    class Config:
        populate_by_name = True

class MetricResponse(SystemMetric):
    id: str = Field(alias="_id")