from typing import Optional
from pydantic import BaseModel


class EventIngest(BaseModel):
    source: str = "unknown"
    event_type: str = "generic"
    raw: dict = {}
    tags: list[str] = []


class EventResponse(BaseModel):
    id: str
    project_id: str
    source: str
    event_type: str
    raw: dict
    enriched: Optional[dict] = None
    tags: list[str] = []
    timestamp: str
