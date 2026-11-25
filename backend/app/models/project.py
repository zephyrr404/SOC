from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str
    type: str
    description: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    id: int
    owner_id: int
    name: str
    type: str
    description: Optional[str] = None
    created_at: datetime
    last_event_time: Optional[datetime] = None
