"""
modules/users/routes.py — User Module Routes

All User and Admin endpoints are defined here.
The existing login, register, smart-login, and OTP flow is fully preserved.
"""
import datetime
import os
import random
import smtplib
import uuid
from email.mime.text import MIMEText

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from config import settings
from database import users_collection
from security import hash_password, verify_password, create_access_token, blacklist_token
from core.helpers import serialize_doc
from core.rate_limiter import login_rate_limiter

from modules.auth.auth import get_current_user, get_admin_user, _bearer_scheme
from modules.users.schemas import (
    UserCreate, UserLogin, UserUpdate, UserResponse,
    ForgotPasswordRequest, VerifyOTPRequest,
    AdminUserResponse, RoleUpdateRequest, Token,
    ProfilePhotoResponse,
)

router = APIRouter()

# ── Upload Configurations ─────────────────────────────────────────────────────
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads", "profile_photos")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/jpg"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _send_otp_email(to_email: str, otp: str) -> bool:
    """Send an OTP to the specified email address via SMTP."""
    try:
        msg = MIMEText(
            f"Your password reset OTP is: {otp}\n\nThis OTP is valid for 10 minutes."
        )
        msg["Subject"] = "Password Reset OTP"
        msg["From"] = settings.EMAIL_USER
        msg["To"] = to_email
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()
            server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
            server.sendmail(settings.EMAIL_USER, to_email, msg.as_string())
        return True
    except Exception as exc:
        print(f"[Email Error] {exc}")
        return False


def _build_user_response(user: dict) -> dict:
    """
    Convert a MongoDB user document to a safe response dictionary.
    Removes sensitive fields: password, access_token, reset_otp, otp_expiry.
    Ensures profile_photo is present.
    """
    doc = serialize_doc(user)
    doc.pop("password", None)
    doc.pop("access_token", None)
    doc.pop("reset_otp", None)
    doc.pop("otp_expiry", None)
    if "profile_photo" not in doc:
        doc["profile_photo"] = None
    return doc


# ─────────────────────────────────────────────────────────────────────────────
# 1. AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/register",
    tags=["Auth"],
    summary="Register a new user account",
    status_code=status.HTTP_201_CREATED,
)
async def register(user_data: UserCreate):
    """
    Create a new user account.

    - **If the username already exists** → returns a 400 error
    - **If the mobile number already exists** → returns a 400 error
    - **If the email is already registered** → returns a token if the password matches
    - **New user** → creates the account and returns 201
    """
    # Check username uniqueness
    if await users_collection.find_one({"username": user_data.username}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists. Please choose another.",
        )

    # Check mobile number uniqueness
    if await users_collection.find_one({"mobile_number": user_data.mobile_number}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mobile number already registered. Please choose another.",
        )

    # If email is already registered, attempt auto-login
    existing = await users_collection.find_one({"email": user_data.email})
    if existing:
        if not verify_password(user_data.password, existing["password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email already registered. Please enter the correct password.",
            )
        token = create_access_token(data={"sub": existing["username"]})
        await users_collection.update_one(
            {"_id": existing["_id"]}, {"$set": {"access_token": token}}
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "access_token": token,
                "token_type": "bearer",
                "message": "Already registered — login successful.",
            },
        )

    # Create a new user account
    now = datetime.datetime.now(datetime.timezone.utc)
    user_doc = {
        "username": user_data.username,
        "email": user_data.email,
        "mobile_number": user_data.mobile_number,
        "gender": user_data.gender,
        "password": hash_password(user_data.password),
        "role": "user",
        "created_at": now,
    }
    result = await users_collection.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    return _build_user_response(user_doc)


@router.post(
    "/login",
    response_model=Token,
    tags=["Auth"],
    summary="Login and get JWT access token (Rate limited: 5 attempts/min)",
    dependencies=[Depends(login_rate_limiter)],
)
async def login(login_data: UserLogin, request: Request):
    """
    Authenticate with email and password.
    Returns a JWT Bearer token on success.

    Rate Limit:
    - Maximum 5 attempts per 1 minute.
    - Exceeding attempts results in HTTP 429 Too Many Requests.
    """
    user = await users_collection.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    # Clear rate limit attempts for this client IP upon successful login
    client_ip = login_rate_limiter.get_client_ip(request)
    login_rate_limiter.reset(f"login:{client_ip}")

    token = create_access_token(data={"sub": user["username"]})
    await users_collection.update_one(
        {"_id": user["_id"]}, {"$set": {"access_token": token}}
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "message": "Login successful.",
    }


@router.post(
    "/logout",
    tags=["Auth"],
    summary="Logout and blacklist current token",
)
async def logout(
    current_user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
):
    """
    Invalidate the current user's session and blacklist the token
    so it cannot be used again.
    """
    token = credentials.credentials
    await blacklist_token(token)
    await users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$unset": {"access_token": ""}},
    )
    return {
        "message": "Logged out successfully. Token has been revoked and cannot be reused."
    }


@router.post(
    "/refresh-token",
    response_model=Token,
    tags=["Auth"],
    summary="Renew access token (Blacklists old token)",
)
async def refresh_token(
    current_user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
):
    """
    Renew the authenticated user's access token.
    The previous token is immediately blacklisted and cannot be reused.
    """
    old_token = credentials.credentials
    await blacklist_token(old_token)

    new_token = create_access_token(data={"sub": current_user["username"]})
    await users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"access_token": new_token}},
    )
    return {
        "access_token": new_token,
        "token_type": "bearer",
        "message": "Token renewed successfully. Previous token has been revoked.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. MY PROFILE ENDPOINTS (Authenticated)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/users/me",
    tags=["Users"],
    summary="Get my profile",
)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """Retrieve the currently authenticated user's profile."""
    return _build_user_response(current_user)


@router.put(
    "/users/me",
    tags=["Users"],
    summary="Update my profile",
)
async def update_my_profile(
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user),
):
    """Update the currently authenticated user's profile."""
    update_data: dict = {}

    if user_update.username:
        conflict = await users_collection.find_one(
            {"username": user_update.username, "_id": {"$ne": current_user["_id"]}}
        )
        if conflict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken.",
            )
        update_data["username"] = user_update.username

    if user_update.email:
        conflict = await users_collection.find_one(
            {"email": user_update.email, "_id": {"$ne": current_user["_id"]}}
        )
        if conflict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already taken.",
            )
        update_data["email"] = user_update.email

    if user_update.mobile_number:
        conflict = await users_collection.find_one(
            {"mobile_number": user_update.mobile_number, "_id": {"$ne": current_user["_id"]}}
        )
        if conflict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mobile number already taken.",
            )
        update_data["mobile_number"] = user_update.mobile_number

    if user_update.gender:
        update_data["gender"] = user_update.gender

    if user_update.password:
        update_data["password"] = hash_password(user_update.password)

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No data provided to update.",
        )

    # If username changed, issue a new token and blacklist the old one
    if "username" in update_data:
        old_token = current_user.get("access_token")
        if old_token:
            await blacklist_token(old_token)
        new_token = create_access_token(data={"sub": update_data["username"]})
        update_data["access_token"] = new_token

    await users_collection.update_one(
        {"_id": current_user["_id"]}, {"$set": update_data}
    )
    updated = await users_collection.find_one({"_id": current_user["_id"]})
    return _build_user_response(updated)


@router.post(
    "/users/me/profile-photo",
    response_model=ProfilePhotoResponse,
    tags=["Users"],
    summary="Upload or update user profile photo",
)
async def upload_profile_photo(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload or update the authenticated user's profile photo.
    - Supported formats: JPEG, PNG, WEBP, GIF
    - Maximum file size: 5 MB
    """
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported image type '{file.content_type}'. Allowed formats: JPEG, PNG, WEBP, GIF.",
        )

    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds maximum limit of 5 MB.",
        )

    # Determine file extension safely
    ext = os.path.splitext(file.filename or "")[1].lower()
    if not ext or ext not in (".jpg", ".jpeg", ".png", ".webp", ".gif"):
        ext = ".jpg" if file.content_type in ("image/jpeg", "image/jpg") else ".png"

    filename = f"{current_user['username']}_{uuid.uuid4().hex[:8]}{ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    # Remove previous uploaded photo file if present locally
    old_photo = current_user.get("profile_photo")
    if old_photo and old_photo.startswith("/uploads/profile_photos/"):
        old_filename = os.path.basename(old_photo)
        old_file_path = os.path.join(UPLOAD_DIR, old_filename)
        if os.path.exists(old_file_path):
            try:
                os.remove(old_file_path)
            except Exception as exc:
                print(f"[Upload Warning] Could not remove old photo: {exc}")

    with open(file_path, "wb") as f:
        f.write(contents)

    photo_url = f"/uploads/profile_photos/{filename}"
    await users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"profile_photo": photo_url}},
    )

    return {
        "message": "Profile photo uploaded successfully.",
        "profile_photo": photo_url,
    }


@router.delete(
    "/users/me/profile-photo",
    tags=["Users"],
    summary="Delete user profile photo",
)
async def delete_profile_photo(current_user: dict = Depends(get_current_user)):
    """Remove the authenticated user's profile photo and delete file from storage."""
    old_photo = current_user.get("profile_photo")
    if not old_photo:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No profile photo to delete.",
        )

    if old_photo.startswith("/uploads/profile_photos/"):
        old_filename = os.path.basename(old_photo)
        old_file_path = os.path.join(UPLOAD_DIR, old_filename)
        if os.path.exists(old_file_path):
            try:
                os.remove(old_file_path)
            except Exception as exc:
                print(f"[Delete Photo Warning] Could not remove photo file: {exc}")

    await users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$unset": {"profile_photo": ""}},
    )
    return {"message": "Profile photo removed successfully."}


@router.delete(
    "/users/me",
    tags=["Users"],
    summary="Delete my account",
)
async def delete_my_account(current_user: dict = Depends(get_current_user)):
    """Permanently delete the currently authenticated user's account."""
    await users_collection.delete_one({"_id": current_user["_id"]})
    return {"message": "Account deleted successfully."}


# ─────────────────────────────────────────────────────────────────────────────
# 3. FORGOT PASSWORD / OTP FLOW
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/forgot-password",
    tags=["Auth"],
    summary="Request password reset OTP",
)
async def forgot_password(request: ForgotPasswordRequest):
    """Generate a 6-digit OTP and send it to the user's email address."""
    user = await users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email.",
        )
    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)
    await users_collection.update_one(
        {"email": request.email},
        {"$set": {"reset_otp": otp, "otp_expiry": otp_expiry}},
    )
    if not _send_otp_email(request.email, otp):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not send OTP email. Check server email configuration.",
        )
    return {"message": f"OTP sent to {request.email}. Valid for 10 minutes."}


@router.post(
    "/reset-password",
    tags=["Auth"],
    summary="Reset password using OTP",
)
async def reset_password(request: VerifyOTPRequest):
    """Verify the OTP and set a new password for the user."""
    user = await users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email.",
        )
    if not user.get("reset_otp"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No OTP requested. Please use /forgot-password first.",
        )
    otp_expiry = user.get("otp_expiry")
    if otp_expiry and datetime.datetime.now(datetime.timezone.utc) > otp_expiry:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new one.",
        )
    if user.get("reset_otp") != request.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP.",
        )
    await users_collection.update_one(
        {"email": request.email},
        {
            "$set": {"password": hash_password(request.new_password)},
            "$unset": {"reset_otp": "", "otp_expiry": ""},
        },
    )
    return {"message": "Password reset successfully! Please login with your new password."}


# ─────────────────────────────────────────────────────────────────────────────
# 4. ADMIN ENDPOINTS (Admin Role Required)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/admin/stats",
    tags=["Admin"],
    summary="Get user statistics (Admin only)",
)
async def get_stats(admin: dict = Depends(get_admin_user)):
    """Return a count of total accounts, regular users, and admins."""
    total_users = await users_collection.count_documents({"role": "user"})
    total_admins = await users_collection.count_documents({"role": "admin"})
    total_all = await users_collection.count_documents({})
    return {
        "total_accounts": total_all,
        "total_users": total_users,
        "total_admins": total_admins,
    }


@router.get(
    "/admin/users",
    tags=["Admin"],
    summary="Get all users (Admin only)",
)
async def get_all_users(admin: dict = Depends(get_admin_user)):
    """Return a list of all registered users. Sensitive fields are excluded."""
    users = []
    async for user in users_collection.find(
        {}, {"password": 0, "access_token": 0, "reset_otp": 0, "otp_expiry": 0}
    ):
        users.append(_build_user_response(user))
    return users


@router.put(
    "/admin/users/{username}/role",
    tags=["Admin"],
    summary="Update user role (Admin only)",
)
async def update_user_role(
    username: str,
    role_data: RoleUpdateRequest,
    admin: dict = Depends(get_admin_user),
):
    """Change the role of any user to 'admin' or 'user'. Admin-only operation."""
    user = await users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found.",
        )
    if user["username"] == admin["username"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role.",
        )
    await users_collection.update_one(
        {"username": username}, {"$set": {"role": role_data.role}}
    )
    return {"message": f"User '{username}' role updated to '{role_data.role}' successfully."}


@router.delete(
    "/admin/users/{username}",
    tags=["Admin"],
    summary="Delete a user (Admin only)",
)
async def admin_delete_user(username: str, admin: dict = Depends(get_admin_user)):
    """Permanently delete any user account. Admin-only operation."""
    user = await users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found.",
        )
    if user["username"] == admin["username"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account via admin panel.",
        )
    await users_collection.delete_one({"username": username})
    return {"message": f"User '{username}' deleted successfully."}
