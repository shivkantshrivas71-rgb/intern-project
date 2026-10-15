"""
security.py — JWT + Password Hashing Utilities
All security logic is centralized here. Settings are loaded from config.py.
"""
import datetime
from typing import Optional

import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError

from config import settings


# ── Password Utilities ────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a plain-text password using bcrypt with 12 salt rounds."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compare a plain-text password against a bcrypt hash. Returns True if they match."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


# ── JWT Utilities ─────────────────────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    """
    Create a signed JWT access token.
    Expiry is set based on the JWT_EXPIRATION_MINUTES value in settings.
    """
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=settings.JWT_EXPIRATION_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    """
    Decode and verify a JWT token. Returns the payload dict if valid.
    Returns None if the token is invalid or has expired.
    """
    try:
        return jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except InvalidTokenError:
        return None


async def blacklist_token(token: str, expires_at: Optional[datetime.datetime] = None) -> bool:
    """
    Store token in blacklisted_tokens collection so it cannot be used again.
    Uses token expiration time for MongoDB TTL automatic cleanup.
    """
    from database import blacklisted_tokens_collection

    if not expires_at:
        payload = verify_token(token)
        if payload and "exp" in payload:
            expires_at = datetime.datetime.fromtimestamp(
                payload["exp"], tz=datetime.timezone.utc
            )
        else:
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                minutes=settings.JWT_EXPIRATION_MINUTES
            )

    try:
        await blacklisted_tokens_collection.update_one(
            {"token": token},
            {
                "$set": {
                    "token": token,
                    "expires_at": expires_at,
                    "blacklisted_at": datetime.datetime.now(datetime.timezone.utc),
                }
            },
            upsert=True,
        )
        return True
    except Exception as exc:
        print(f"[Security] Error blacklisting token: {exc}")
        return False


async def is_token_blacklisted(token: str) -> bool:
    """
    Check if a token has been revoked / blacklisted.
    Returns True if blacklisted, False otherwise.
    """
    from database import blacklisted_tokens_collection
    doc = await blacklisted_tokens_collection.find_one({"token": token})
    return doc is not None

