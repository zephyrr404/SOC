from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class ApiKeyCreate(BaseModel):
    label: str


class ApiKeyResponse(BaseModel):
    id: int
    project_id: int
    label: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    revoked: bool


class ApiKeyCreated(BaseModel):
    id: int
    label: str
    key: str
    created_at: datetime
