"""
modules/auth/auth.py — JWT Authentication Layer (Dependency Injection)

This module defines request-level authentication dependencies.
It integrates with FastAPI's Depends() system.

Usage in protected routes:
    current_user = Depends(get_current_user)
    admin_user   = Depends(get_admin_user)
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import users_collection
from security import verify_token, is_token_blacklisted

# ── Bearer Token Scheme ───────────────────────────────────────────────────────
_bearer_scheme = HTTPBearer()


# ── Core Authentication Dependency ───────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> dict:
    """
    Authentication dependency for all protected routes.

    Steps:
    1. Extract the Bearer token from the Authorization header
    2. Verify the JWT signature and expiry
    3. Check if the token has been revoked / blacklisted
    4. Look up the user in the database
    5. Validate the active session token (single-device session control)

    Returns: The full user document (dict) from MongoDB.
    Raises:  401 if the token is invalid, expired, or revoked; 404 if user not found.
    """
    token = credentials.credentials

    # Step 1: Verify the JWT token
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token. Please login again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Step 2: Check if the token has been blacklisted / revoked
    if await is_token_blacklisted(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked or logged out. Please login again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username: str = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload invalid — 'sub' claim missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Step 2: Look up the user in the database
    user = await users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found. Account may have been deleted.",
        )

    # Step 3: Match the active session token (single-device session)
    if user.get("access_token") != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or logged in from another device.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# ── Role-Based Authorization Dependency ──────────────────────────────────────

async def get_admin_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Authorization dependency for admin-only routes.
    Chained on top of get_current_user.

    Returns: The user document if role == 'admin'.
    Raises:  403 Forbidden if the user does not have admin privileges.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied. Admin privileges required for this endpoint.",
        )
    return current_user
