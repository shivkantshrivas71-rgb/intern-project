import datetime
import re
from pydantic import BaseModel, Field, field_validator

class UserCreate(BaseModel):
    username: str = Field(..., examples=["john_doe"])
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., examples=["StrongPassword123"])
    mobile_number: str = Field(..., examples=["9876543210"])
    gender: str = Field(..., examples=["male", "female", "other"])

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v

    @field_validator('mobile_number')
    @classmethod
    def validate_mobile(cls, v):
        clean_v = v.strip().replace(" ", "").replace("-", "")
        if not re.match(r"^\+?[0-9]{10,15}$", clean_v):
            raise ValueError("Invalid mobile number format. Must be 10-15 digits.")
        return clean_v

    @field_validator('gender')
    @classmethod
    def validate_gender(cls, v):
        cleaned = v.strip().lower()
        if cleaned not in ("male", "female", "other"):
            raise ValueError("Gender must be 'male', 'female', or 'other'")
        return cleaned

class UserLogin(BaseModel):
    email: str = Field(..., description="Enter your registered email")
    password: str = Field(..., examples=["StrongPassword123"])

class UserUpdate(BaseModel):
    username: str | None = Field(None, examples=["new_username"])
    email: str | None = Field(None, examples=["user@example.com"])
    password: str | None = Field(None, examples=["NewPassword123"])
    mobile_number: str | None = Field(None, examples=["9876543210"])
    gender: str | None = Field(None, examples=["male"])

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v is not None and not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v

    @field_validator('mobile_number')
    @classmethod
    def validate_mobile(cls, v):
        if v is not None:
            clean_v = v.strip().replace(" ", "").replace("-", "")
            if not re.match(r"^\+?[0-9]{10,15}$", clean_v):
                raise ValueError("Invalid mobile number format. Must be 10-15 digits.")
            return clean_v
        return v

    @field_validator('gender')
    @classmethod
    def validate_gender(cls, v):
        if v is not None:
            cleaned = v.strip().lower()
            if cleaned not in ("male", "female", "other"):
                raise ValueError("Gender must be 'male', 'female', or 'other'")
            return cleaned
        return v

class UserResponse(BaseModel):
    username: str
    email: str | None = None
    mobile_number: str | None = None
    gender: str | None = None
    profile_photo: str | None = None
    created_at: datetime.datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    message: str | None = None

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., examples=["user@example.com"])

class VerifyOTPRequest(BaseModel):
    email: str = Field(..., examples=["user@example.com"])
    otp: str = Field(..., examples=["123456"])
    new_password: str = Field(..., examples=["NewPassword123"])

# ==========================================
# ADMIN SCHEMAS
# ==========================================

class AdminUserResponse(BaseModel):
    """Admin ke liye full user details (role ke saath)"""
    username: str
    email: str | None = None
    mobile_number: str | None = None
    gender: str | None = None
    profile_photo: str | None = None
    role: str = "user"
    created_at: datetime.datetime

class RoleUpdateRequest(BaseModel):
    """Admin kisi bhi user ka role change kar sakta hai"""
    role: str = Field(..., examples=["admin", "user"], description="New role: 'admin' ya 'user'")
