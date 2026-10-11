"""
modules/agents/schemas.py — Agent Module Pydantic v2 Schemas

Schemas for the business operational Agent structure.
No password hashing — standard fields: name, phone, email, status.
"""
import datetime
import re
from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator, ConfigDict

from core.helpers import ObjId


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class AgentCreate(BaseModel):
    """Input schema for creating a new agent record."""
    name: str = Field(..., min_length=2, max_length=100, examples=["Rahul Kumar"])
    phone: str = Field(..., examples=["+919876543210"])
    email: Optional[str] = Field(None, examples=["rahul@example.com"])
    status: Literal["active", "inactive", "suspended"] = Field(
        default="active",
        description="Current operational status of the agent",
    )
    region: Optional[str] = Field(None, max_length=100, examples=["Mumbai"])
    department: Optional[str] = Field(None, max_length=100, examples=["Sales"])
    notes: Optional[str] = Field(None, max_length=500, examples=["Senior agent with 5 years experience"])

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        cleaned = re.sub(r"[\s\-\(\)]", "", v)
        if not re.match(r"^\+?[1-9]\d{7,14}$", cleaned):
            raise ValueError("Invalid phone number format")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v.lower().strip() if v else v


class AgentUpdate(BaseModel):
    """Schema for updating an agent's fields. All fields are optional."""
    name: Optional[str] = Field(None, min_length=2, max_length=100, examples=["Rahul Kumar"])
    phone: Optional[str] = Field(None, examples=["+919876543210"])
    email: Optional[str] = Field(None, examples=["rahul@example.com"])
    status: Optional[Literal["active", "inactive", "suspended"]] = Field(None)
    region: Optional[str] = Field(None, max_length=100)
    department: Optional[str] = Field(None, max_length=100)
    notes: Optional[str] = Field(None, max_length=500)

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = re.sub(r"[\s\-\(\)]", "", v)
        if not re.match(r"^\+?[1-9]\d{7,14}$", cleaned):
            raise ValueError("Invalid phone number format")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v.lower().strip() if v else v


# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class AgentResponse(BaseModel):
    """Full response schema for a single agent record."""
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[ObjId] = Field(None, alias="_id")
    name: str
    phone: str
    email: Optional[str] = None
    status: str = "active"
    region: Optional[str] = None
    department: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime.datetime
    updated_at: Optional[datetime.datetime] = None


class AgentListResponse(BaseModel):
    """Response schema for a paginated list of agents."""
    total: int
    page: int
    page_size: int
    agents: list[AgentResponse]
