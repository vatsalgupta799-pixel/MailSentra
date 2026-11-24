"""User schemas for authentication and profile management."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from app.models.user import UserRole


class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = UserRole.SOC_ANALYST


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128, description="Password (min 8 chars)")


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int


class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None


class IngestionActor(BaseModel):
    """Represents an authenticated ingestion actor (API Key collector or User)."""
    identity: str
    role: str
    is_api_key: bool = False
    tenant_id: str = "default"
    user: Optional[UserResponse] = None
