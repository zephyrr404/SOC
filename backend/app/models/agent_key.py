from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


def generate_key_prefix() -> str:
    return secrets.token_hex(6)


def hash_raw_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_raw_key() -> str:
    return f"sak_{secrets.token_urlsafe(32)}"


class AgentKeyCreate(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    project_id: int


class AgentKeyResponse(BaseModel):
    id: int
    label: str
    key_prefix: str
    status: str
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    project_id: Optional[int] = None
    created_at: datetime
    enrolled_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class AgentKeyCreated(BaseModel):
    id: int
    label: str
    api_key: str
    status: str


class EnrollRequest(BaseModel):
    api_key: str
    hostname: str
    os_type: str
    ip_address: str
    fingerprint_seed: str


class EnrollResponse(BaseModel):
    agent_token: str
    agent_id: int
    log_endpoint: str


class AgentLogEntry(BaseModel):
    level: str = "info"
    stage: str
    message: str
    meta: dict = {}


class AgentLogBulkEntry(BaseModel):
    level: str = "info"
    stage: str
    message: str
    meta: dict = {}
    event_time: Optional[str] = None


class AgentLogBulk(BaseModel):
    entries: list[AgentLogBulkEntry] = Field(max_length=1000)
