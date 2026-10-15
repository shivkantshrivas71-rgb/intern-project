"""
modules/users/schemas.py — User Module Pydantic v2 Schemas

All request and response models for the User module are defined here.
PyObjectId is used to handle the MongoDB _id → JSON string conversion.
"""
import datetime
import re
from typing import Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict

from core.helpers import ObjId


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    """Input schema for registering a new user account."""
    username: str = Field(..., min_length=3, max_length=50, examples=["john_doe"])
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., min_length=6, examples=["StrongPassword123"])
    mobile_number: str = Field(..., examples=["9876543210"])
    gender: str = Field(..., examples=["male", "female", "other"])

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v.lower().strip()

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return v.lower().strip()

    @field_validator("mobile_number")
    @classmethod
    def validate_mobile(cls, v: str) -> str:
        clean_v = v.strip().replace(" ", "").replace("-", "")
        if not re.match(r"^\+?[0-9]{10,15}$", clean_v):
            raise ValueError("Invalid mobile number format. Must be 10-15 digits.")
        return clean_v

    @field_validator("gender")
    @classmethod
    def validate_gender(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if cleaned not in ("male", "female", "other"):
            raise ValueError("Gender must be 'male', 'female', or 'other'")
        return cleaned


class UserLogin(BaseModel):
    """Credentials required to log in."""
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., examples=["StrongPassword123"])


class UserUpdate(BaseModel):
    """Schema for updating a user's own profile. All fields are optional."""
    username: Optional[str] = Field(None, min_length=3, max_length=50, examples=["new_username"])
    email: Optional[str] = Field(None, examples=["new@example.com"])
    password: Optional[str] = Field(None, min_length=6, examples=["NewPassword123"])
    mobile_number: Optional[str] = Field(None, examples=["9876543210"])
    gender: Optional[str] = Field(None, examples=["male"])

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v.lower().strip() if v else v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return v.lower().strip() if v else v

    @field_validator("mobile_number")
    @classmethod
    def validate_mobile(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            clean_v = v.strip().replace(" ", "").replace("-", "")
            if not re.match(r"^\+?[0-9]{10,15}$", clean_v):
                raise ValueError("Invalid mobile number format. Must be 10-15 digits.")
            return clean_v
        return v

    @field_validator("gender")
    @classmethod
    def validate_gender(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            cleaned = v.strip().lower()
            if cleaned not in ("male", "female", "other"):
                raise ValueError("Gender must be 'male', 'female', or 'other'")
            return cleaned
        return v


class ForgotPasswordRequest(BaseModel):
    """Request schema for initiating a password reset via OTP."""
    email: str = Field(..., examples=["user@example.com"])


class VerifyOTPRequest(BaseModel):
    """Request schema for verifying an OTP and setting a new password."""
    email: str = Field(..., examples=["user@example.com"])
    otp: str = Field(..., min_length=6, max_length=6, examples=["123456"])
    new_password: str = Field(..., min_length=6, examples=["NewPassword123"])


class RoleUpdateRequest(BaseModel):
    """Admin-only schema for updating a user's role."""
    role: str = Field(..., examples=["admin", "user"])

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("admin", "user"):
            raise ValueError("Role must be 'admin' or 'user'")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    """Public user profile response — password is always excluded."""
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[ObjId] = Field(None, alias="_id")
    username: str
    email: Optional[str] = None
    mobile_number: Optional[str] = None
    gender: Optional[str] = None
    role: str = "user"
    profile_photo: Optional[str] = None
    created_at: datetime.datetime


class AdminUserResponse(BaseModel):
    """Full user details returned to admin users."""
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[ObjId] = Field(None, alias="_id")
    username: str
    email: Optional[str] = None
    mobile_number: Optional[str] = None
    gender: Optional[str] = None
    role: str = "user"
    profile_photo: Optional[str] = None
    created_at: datetime.datetime


class Token(BaseModel):
    """JWT token response returned after a successful login or refresh."""
    access_token: str
    token_type: str = "bearer"
    message: Optional[str] = None


class ProfilePhotoResponse(BaseModel):
    """Response returned when a profile photo is uploaded or removed."""
    message: str
    profile_photo: Optional[str] = None

