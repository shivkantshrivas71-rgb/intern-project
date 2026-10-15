"""
main.py — Master API Gateway (Central Application Entry Point)

All API endpoints are defined directly here for complete clarity,
easy navigation, and unified OpenAPI/Swagger documentation without duplicates.

Endpoints Overview:
    - Health & Root:     GET / , GET /health
    - Authentication:    POST /register , POST /login , POST /logout , POST /refresh-token
                         POST /forgot-password , POST /reset-password
    - User Profile:      GET /users/me , PUT /users/me , DELETE /users/me
                         POST /users/me/profile-photo , DELETE /users/me/profile-photo
    - Admin Operations:  GET /admin/stats , GET /admin/users
                         PUT /admin/users/{username}/role , DELETE /admin/users/{username}
    - Agents Operations: POST /agents/ , GET /agents/ , GET /agents/{agent_id}
                         PUT /agents/{agent_id} , DELETE /agents/{agent_id}
                         PATCH /agents/bulk/status

Run Server:
    uvicorn main:app --reload
"""
import datetime
import os
import random
import smtplib
import uuid
from contextlib import asynccontextmanager
from email.mime.text import MIMEText
from typing import Optional

from bson import ObjectId
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Query,
    Request,
    UploadFile,
    File,
    status,
)
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles

from config import settings
from database import users_collection, agents_collection, create_db_indexes
from middleware import setup_middlewares
from security import (
    hash_password,
    verify_password,
    create_access_token,
    blacklist_token,
)
from core.helpers import serialize_doc, serialize_list
from core.rate_limiter import login_rate_limiter
from modules.auth.auth import get_current_user, get_admin_user, _bearer_scheme

# Schemas
from modules.users.schemas import (
    UserCreate,
    UserLogin,
    UserUpdate,
    UserResponse,
    AdminUserResponse,
    RoleUpdateRequest,
    Token,
    ForgotPasswordRequest,
    VerifyOTPRequest,
    ProfilePhotoResponse,
)
from modules.agents.schemas import (
    AgentCreate,
    AgentUpdate,
    AgentResponse,
    AgentListResponse,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads", "profile_photos")
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/jpg"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPER FUNCTIONS
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
        print(f"[Email Error] Could not send OTP email: {exc}")
        return False


def _build_user_response(user: dict) -> dict:
    """
    Convert a MongoDB user document to a safe public/authenticated dictionary.
    Removes sensitive secrets: password, access_token, reset_otp, otp_expiry.
    """
    doc = serialize_doc(user)
    doc.pop("password", None)
    doc.pop("access_token", None)
    doc.pop("reset_otp", None)
    doc.pop("otp_expiry", None)
    if "profile_photo" not in doc:
        doc["profile_photo"] = None
    return doc


async def _get_agent_or_404(agent_id: str) -> dict:
    """Validate MongoDB ObjectId and return agent document or raise 404/422."""
    if not ObjectId.is_valid(agent_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid agent ID format: '{agent_id}'",
        )
    agent = await agents_collection.find_one({"_id": ObjectId(agent_id)})
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with ID '{agent_id}' not found.",
        )
    return agent


# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION LIFESPAN (Startup / Shutdown)
# ─────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager.
    Startup:  Ensures upload directories exist and creates MongoDB indexes.
    Shutdown: Closes active resources gracefully.
    """
    # ── STARTUP ──────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  {settings.APP_TITLE} v{settings.APP_VERSION}")
    print(f"  Starting up... verifying MongoDB connection & indexes")
    print(f"{'='*60}\n")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    await create_db_indexes()

    print("[Gateway] All database indexes and directories ready. API is live.\n")
    # ─────────────────────────────────────────────────────────

    yield

    # ── SHUTDOWN ─────────────────────────────────────────────
    print("\n[Gateway] Shutting down gracefully...")


# ─────────────────────────────────────────────────────────────────────────────
# FASTAPI APPLICATION INSTANCE
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Setup Middlewares (CORS + Security Headers)
setup_middlewares(app)

# Mount Static Files for Profile Photos
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


# ─────────────────────────────────────────────────────────────────────────────
# 1. HEALTH & ROOT ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"], summary="API root health check")
async def root():
    """Master API Gateway root health check endpoint."""
    return JSONResponse(
        content={
            "status": "healthy",
            "app": settings.APP_TITLE,
            "version": settings.APP_VERSION,
            "documentation": {
                "swagger": "/docs",
                "redoc": "/redoc",
            },
            "modules": ["auth", "users", "admin", "agents"],
        }
    )


@app.get("/health", tags=["Health"], summary="Detailed health status")
async def health_check():
    """Return detailed health status and categorized list of all endpoints."""
    return {
        "status": "ok",
        "database": "mongodb",
        "endpoints": {
            "auth": [
                "POST   /register",
                "POST   /login",
                "POST   /logout",
                "POST   /refresh-token",
                "POST   /forgot-password",
                "POST   /reset-password",
            ],
            "users": [
                "GET    /users/me",
                "PUT    /users/me",
                "DELETE /users/me",
                "POST   /users/me/profile-photo",
                "DELETE /users/me/profile-photo",
            ],
            "admin": [
                "GET    /admin/stats",
                "GET    /admin/users",
                "PUT    /admin/users/{username}/role",
                "DELETE /admin/users/{username}",
            ],
            "agents": [
                "POST   /agents/",
                "GET    /agents/",
                "GET    /agents/{agent_id}",
                "PUT    /agents/{agent_id}",
                "DELETE /agents/{agent_id}",
                "PATCH  /agents/bulk/status",
            ],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. AUTHENTICATION ENDPOINTS (tags=["Auth"])
# ─────────────────────────────────────────────────────────────────────────────
@app.post(
    "/register",
    tags=["Auth"],
    summary="Register a new user account",
    status_code=status.HTTP_201_CREATED,
)
async def register(user_data: UserCreate):
    """
    Create a new user account.
    - If username already exists -> 400 Bad Request
    - If mobile number already exists -> 400 Bad Request
    - If email already exists and password matches -> auto-login token returned
    - New user -> creates account with hashed password and returns safe user profile
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

    # Check email: if registered, verify password and auto-login
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

    # Create new user record
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


@app.post(
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
    - Exceeding attempts triggers HTTP 429 Too Many Requests.
    """
    user = await users_collection.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    # Reset rate limiter upon successful login
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


@app.post(
    "/logout",
    tags=["Auth"],
    summary="Logout and blacklist current token",
)
async def logout(
    current_user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
):
    """
    Invalidate active user session and blacklist the current JWT token permanently.
    The revoked token cannot be reused.
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


@app.post(
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
    Renew active user token.
    The previous token is immediately blacklisted to prevent token reuse.
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


@app.post(
    "/forgot-password",
    tags=["Auth"],
    summary="Request password reset OTP",
)
async def forgot_password(request: ForgotPasswordRequest):
    """Generate a 6-digit OTP and send it to the registered email address."""
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


@app.post(
    "/reset-password",
    tags=["Auth"],
    summary="Reset password using OTP",
)
async def reset_password(request: VerifyOTPRequest):
    """Verify OTP and set a new bcrypt-hashed password."""
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
# 3. USER PROFILE ENDPOINTS (tags=["Users"])
# ─────────────────────────────────────────────────────────────────────────────
@app.get(
    "/users/me",
    tags=["Users"],
    summary="Get my profile",
)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """Retrieve authenticated user's profile with sensitive credentials excluded."""
    return _build_user_response(current_user)


@app.put(
    "/users/me",
    tags=["Users"],
    summary="Update my profile",
)
async def update_my_profile(
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_user),
):
    """
    Update profile details for the authenticated user.
    Checks uniqueness for username, email, and mobile_number.
    If username changes, revokes the old token and issues a new one.
    """
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

    # When username changes, invalidate old token and issue new token
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


@app.post(
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
    Upload or replace user profile photo.
    - Supported formats: JPEG, PNG, WEBP, GIF
    - Maximum file size: 5 MB
    - Replaces previous local photo file cleanly
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

    # Determine extension
    ext = os.path.splitext(file.filename or "")[1].lower()
    if not ext or ext not in (".jpg", ".jpeg", ".png", ".webp", ".gif"):
        ext = ".jpg" if file.content_type in ("image/jpeg", "image/jpg") else ".png"

    filename = f"{current_user['username']}_{uuid.uuid4().hex[:8]}{ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    # Remove previous photo from local storage if exists
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


@app.delete(
    "/users/me/profile-photo",
    tags=["Users"],
    summary="Delete user profile photo",
)
async def delete_profile_photo(current_user: dict = Depends(get_current_user)):
    """Remove user's profile photo and delete file from local storage."""
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


@app.delete(
    "/users/me",
    tags=["Users"],
    summary="Delete my account",
)
async def delete_my_account(current_user: dict = Depends(get_current_user)):
    """Permanently delete authenticated user's account."""
    # Delete uploaded profile photo if exists
    old_photo = current_user.get("profile_photo")
    if old_photo and old_photo.startswith("/uploads/profile_photos/"):
        old_filename = os.path.basename(old_photo)
        old_file_path = os.path.join(UPLOAD_DIR, old_filename)
        if os.path.exists(old_file_path):
            try:
                os.remove(old_file_path)
            except Exception:
                pass

    await users_collection.delete_one({"_id": current_user["_id"]})
    return {"message": "Account deleted successfully."}


# ─────────────────────────────────────────────────────────────────────────────
# 4. ADMIN ENDPOINTS (tags=["Admin"])
# ─────────────────────────────────────────────────────────────────────────────
@app.get(
    "/admin/stats",
    tags=["Admin"],
    summary="Get user statistics (Admin only)",
)
async def get_stats(admin: dict = Depends(get_admin_user)):
    """Return count of total accounts, standard users, and administrators."""
    total_users = await users_collection.count_documents({"role": "user"})
    total_admins = await users_collection.count_documents({"role": "admin"})
    total_all = await users_collection.count_documents({})
    return {
        "total_accounts": total_all,
        "total_users": total_users,
        "total_admins": total_admins,
    }


@app.get(
    "/admin/users",
    tags=["Admin"],
    summary="Get all users (Admin only)",
)
async def get_all_users(admin: dict = Depends(get_admin_user)):
    """Return a list of all registered users. Sensitive credentials excluded."""
    users = []
    async for user in users_collection.find(
        {}, {"password": 0, "access_token": 0, "reset_otp": 0, "otp_expiry": 0}
    ):
        users.append(_build_user_response(user))
    return users


@app.put(
    "/admin/users/{username}/role",
    tags=["Admin"],
    summary="Update user role (Admin only)",
)
async def update_user_role(
    username: str,
    role_data: RoleUpdateRequest,
    admin: dict = Depends(get_admin_user),
):
    """Change role of any user to 'admin' or 'user'. Cannot modify own role."""
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


@app.delete(
    "/admin/users/{username}",
    tags=["Admin"],
    summary="Delete a user (Admin only)",
)
async def admin_delete_user(username: str, admin: dict = Depends(get_admin_user)):
    """Permanently delete any user account (Admin only). Cannot delete self."""
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


# ─────────────────────────────────────────────────────────────────────────────
# 5. AGENTS MANAGEMENT ENDPOINTS (tags=["Agents"])
# ─────────────────────────────────────────────────────────────────────────────
@app.post(
    "/agents/",
    tags=["Agents"],
    summary="Create a new agent",
    status_code=status.HTTP_201_CREATED,
)
async def create_agent(
    agent_data: AgentCreate,
    current_user: dict = Depends(get_current_user),
):
    """
    Create a new operational agent record.
    - Phone number must be unique across all agents.
    - Requires authentication.
    """
    if await agents_collection.find_one({"phone": agent_data.phone}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Agent with phone '{agent_data.phone}' already exists.",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    agent_doc = {
        **agent_data.model_dump(exclude_none=False),
        "created_by": current_user["username"],
        "created_at": now,
        "updated_at": now,
    }
    result = await agents_collection.insert_one(agent_doc)
    agent_doc["_id"] = result.inserted_id
    return serialize_doc(agent_doc)


@app.get(
    "/agents/",
    tags=["Agents"],
    summary="Get all agents (paginated)",
)
async def list_agents(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=10, ge=1, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(
        default=None,
        alias="status",
        description="Filter by status: active/inactive/suspended",
    ),
    search: Optional[str] = Query(default=None, description="Search by name or phone"),
    current_user: dict = Depends(get_current_user),
):
    """
    Return a paginated list of all agents.
    Supports optional status filtering and name/phone search query.
    """
    query: dict = {}

    if status_filter:
        if status_filter not in ("active", "inactive", "suspended"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status filter. Allowed values: active, inactive, suspended.",
            )
        query["status"] = status_filter

    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"phone": {"$regex": search, "$options": "i"}},
        ]

    total = await agents_collection.count_documents(query)
    skip = (page - 1) * page_size

    cursor = agents_collection.find(query).skip(skip).limit(page_size).sort("created_at", -1)
    agents = await cursor.to_list(length=page_size)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": serialize_list(agents),
    }


@app.get(
    "/agents/{agent_id}",
    tags=["Agents"],
    summary="Get a single agent by ID",
)
async def get_agent(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Fetch details of a single agent by their MongoDB ObjectId."""
    agent = await _get_agent_or_404(agent_id)
    return serialize_doc(agent)


@app.put(
    "/agents/{agent_id}",
    tags=["Agents"],
    summary="Update an existing agent",
)
async def update_agent(
    agent_id: str,
    agent_data: AgentUpdate,
    current_user: dict = Depends(get_current_user),
):
    """
    Update details of an existing agent.
    If phone is updated, verifies uniqueness across other records.
    """
    agent = await _get_agent_or_404(agent_id)

    update_dict = agent_data.model_dump(exclude_unset=True)
    if not update_dict:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields provided to update.",
        )

    # Check phone uniqueness if modified
    if "phone" in update_dict and update_dict["phone"] != agent.get("phone"):
        existing_phone = await agents_collection.find_one(
            {"phone": update_dict["phone"], "_id": {"$ne": ObjectId(agent_id)}}
        )
        if existing_phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"An agent with phone '{update_dict['phone']}' already exists.",
            )

    update_dict["updated_at"] = datetime.datetime.now(datetime.timezone.utc)
    await agents_collection.update_one(
        {"_id": ObjectId(agent_id)}, {"$set": update_dict}
    )
    updated = await agents_collection.find_one({"_id": ObjectId(agent_id)})
    return serialize_doc(updated)


@app.delete(
    "/agents/{agent_id}",
    tags=["Agents"],
    summary="Delete an agent (Admin only)",
)
async def delete_agent(
    agent_id: str,
    admin: dict = Depends(get_admin_user),
):
    """Permanently delete an agent record (Admin only)."""
    await _get_agent_or_404(agent_id)
    await agents_collection.delete_one({"_id": ObjectId(agent_id)})
    return {"message": f"Agent '{agent_id}' deleted successfully."}


@app.patch(
    "/agents/bulk/status",
    tags=["Agents"],
    summary="Bulk update agent status (Admin only)",
)
async def bulk_update_status(
    agent_ids: list[str],
    new_status: str = Query(..., description="New status: active/inactive/suspended"),
    admin: dict = Depends(get_admin_user),
):
    """Update status of multiple agents in one request (Admin only)."""
    if new_status not in ("active", "inactive", "suspended"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid status. Use: active, inactive, or suspended.",
        )

    valid_ids = []
    for aid in agent_ids:
        if not ObjectId.is_valid(aid):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid agent ID format: '{aid}'",
            )
        valid_ids.append(ObjectId(aid))

    result = await agents_collection.update_many(
        {"_id": {"$in": valid_ids}},
        {
            "$set": {
                "status": new_status,
                "updated_at": datetime.datetime.now(datetime.timezone.utc),
            }
        },
    )
    return {
        "matched": result.matched_count,
        "modified": result.modified_count,
        "message": f"{result.modified_count} agent(s) updated to status '{new_status}'.",
    }
