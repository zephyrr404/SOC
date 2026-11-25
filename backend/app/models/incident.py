from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class IncidentContext(BaseModel):
    """Optional creation context used for auto-titling (event/chain source)."""

    hostname: Optional[str] = None
    technique: Optional[str] = None
    event_summary: Optional[str] = None


class IncidentCreate(BaseModel):
    title: Optional[str] = ""
    description: Optional[str] = None
    severity: str = "medium"
    context: Optional[IncidentContext] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[int] = None
    tags: Optional[list[str]] = None
    resolution_note: Optional[str] = None


class IncidentResponse(BaseModel):
    id: int
    project_id: int
    title: str
    description: Optional[str] = None
    mitigation: Optional[list] = None
    severity: str
    status: str
    assigned_to: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    notes: list[dict] = []
    os_types: list[str] = []
    affected_ips: list[str] = []
    hosts: list[str] = []
    users: list[str] = []
    technique_ids: list[str] = []
    tags: list[str] = []
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None
    risk_score: Optional[float] = None
    risk_average: Optional[float] = None
    mitre_tags: list[dict] = []
    primary_ip: Optional[str] = None
