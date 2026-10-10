import datetime
import re
from pydantic import BaseModel, Field, field_validator

class UserCreate(BaseModel):
    username: str = Field(..., examples=["john_doe"])
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., examples=["StrongPassword123"])

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v

class UserLogin(BaseModel):
    email: str = Field(..., description="Enter your registered email")
    password: str = Field(..., examples=["StrongPassword123"])

class UserUpdate(BaseModel):
    username: str | None = Field(None, examples=["new_username"])
    email: str | None = Field(None, examples=["user@example.com"])
    password: str | None = Field(None, examples=["NewPassword123"])

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v is not None and not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v

class UserResponse(BaseModel):
    username: str
    email: str | None = None
    created_at: datetime.datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., examples=["user@example.com"])

class VerifyOTPRequest(BaseModel):
    email: str = Field(..., examples=["user@example.com"])
    otp: str = Field(..., examples=["123456"])
    new_password: str = Field(..., examples=["NewPassword123"])

class SmartLoginRequest(BaseModel):
    """
    Smart Login/Register:
    - Agar user already registered hai → password se login kar lega
    - Agar user naya hai → username bhi dena hoga, account bana dega aur login kar dega
    """
    email: str = Field(..., examples=["user@example.com"])
    password: str = Field(..., examples=["StrongPassword123"])
    username: str | None = Field(
        None,
        description="Sirf tab zaroori hai jab aap naya account bana rahe hain",
        examples=["john_doe"]
    )

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError("Invalid email format")
        return v

class SmartLoginResponse(BaseModel):
    access_token: str
    token_type: str
    is_new_user: bool = Field(..., description="True = naya account bana, False = purani email se login hua")

# ==========================================
# ADMIN SCHEMAS
# ==========================================

class AdminUserResponse(BaseModel):
    """Admin ke liye full user details (role ke saath)"""
    username: str
    email: str | None = None
    role: str = "user"
    created_at: datetime.datetime

class RoleUpdateRequest(BaseModel):
    """Admin kisi bhi user ka role change kar sakta hai"""
    role: str = Field(..., examples=["admin", "user"], description="New role: 'admin' ya 'user'")
