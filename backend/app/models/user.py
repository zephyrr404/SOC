from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=6, max_length=72)
    name: str = Field(min_length=1, max_length=100)


class UserLogin(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=72)


class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    created_at: datetime
    current_project_id: Optional[int] = None
