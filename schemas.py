import datetime
import re
from pydantic import BaseModel, Field, field_validator

class UserCreate(BaseModel):
    username: str = Field(..., examples=["please enter your name"])
    password: str = Field(..., examples=["please enter your password"])

class UserLogin(BaseModel):
    username_or_email: str = Field(..., description="Enter your username or email")
    password: str = Field(..., examples=["please enter your password"])

class UserUpdate(BaseModel):
    username: str | None = Field(None, examples=["please enter your name"])
    email: str | None = Field(None, examples=["user@example.com"])
    password: str | None = Field(None, examples=["please enter your password"])

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
