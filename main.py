import datetime
import random
import smtplib
import os
from email.mime.text import MIMEText
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
from bson import ObjectId
from dotenv import load_dotenv

load_dotenv()

# Import functions and configurations from other files
from database import users_collection, create_db_indexes
from security import hash_password, verify_password, create_access_token, verify_token
from schemas import UserCreate, UserUpdate, UserResponse, Token, UserLogin, ForgotPasswordRequest, VerifyOTPRequest, SmartLoginRequest, SmartLoginResponse, AdminUserResponse, RoleUpdateRequest
from middleware import setup_middlewares

# Email config from .env
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")

def send_otp_email(to_email: str, otp: str):
    """Send OTP to user's email via SMTP."""
    try:
        msg = MIMEText(f"Your password reset OTP is: {otp}\n\nThis OTP is valid for 10 minutes.")
        msg['Subject'] = "Password Reset OTP"
        msg['From'] = EMAIL_USER
        msg['To'] = to_email

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"Email send error: {e}")
        return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run database setup on app startup
    await create_db_indexes()
    yield

app = FastAPI(title="Complete FastAPI Auth & CRUD", lifespan=lifespan)

# Setup middlewares (CORS and Security Headers)
setup_middlewares(app)

@app.get("/")
async def root():
    return {
        "message": "Welcome to the FastAPI Auth & CRUD API!", 
        "documentation": "Visit /docs to see all available endpoints and test them."
    }

# ==========================================
# 1. LOGIN VERIFICATION (Dependency)
# ==========================================
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Check if the user has a valid login token."""
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or Expired Token")
    
    user = await users_collection.find_one({"username": payload.get("sub")})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Check if the token matches the one in the database
    if user.get("access_token") != token:
        raise HTTPException(status_code=401, detail="Token is invalid or user logged in from another device")
        
    return user

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    """Check karo ki logged-in user Admin hai ya nahi."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied! Sirf Admins hi ye endpoint use kar sakte hain."
        )
    return current_user


# ==========================================
# 2. USER ENDPOINTS (Register, Login, Update Profile)
# ==========================================
@app.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    # Step 1: Check if the username already exists
    if await users_collection.find_one({"username": user_data.username}):
        raise HTTPException(status_code=400, detail="Username already exists")

    # Step 2: Agar email already registered hai to seedha login kar do
    existing_user = await users_collection.find_one({"email": user_data.email})
    if existing_user:
        # Password check karo
        if not verify_password(user_data.password, existing_user["password"]):
            raise HTTPException(status_code=401, detail="Email already registered hai. Sahi password enter karein.")
        # Sahi password → seedha login token return karo
        token = create_access_token(data={"sub": existing_user["username"]})
        await users_collection.update_one(
            {"_id": existing_user["_id"]},
            {"$set": {"access_token": token}}
        )
        return JSONResponse(content={"access_token": token, "token_type": "bearer", "message": "Already registered — login successful"})

    # Step 3: Naya user — account banao
    user_doc = {
        "username": user_data.username,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "role": "user",  # Default role
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }
    await users_collection.insert_one(user_doc)
    return {"username": user_doc["username"], "email": user_doc["email"], "created_at": user_doc["created_at"]}

@app.post("/login", response_model=Token)
async def login(login_data: UserLogin):
    # Step 1: Find the user by email
    user = await users_collection.find_one({"email": login_data.email})
    
    # Step 2: If user not found or password wrong, show error
    if not user or not verify_password(login_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
        
    # Step 3: Create a new login token
    token = create_access_token(data={"sub": user["username"]})
    
    # Step 4: Save the token in the database
    await users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"access_token": token}}
    )
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"], "email": current_user.get("email"), "created_at": current_user["created_at"]}

@app.put("/users/me", response_model=UserResponse)
async def update_my_profile(user_update: UserUpdate, current_user: dict = Depends(get_current_user)):
    update_data = {}

    # Username update — check karo koi aur use nahi kar raha
    if user_update.username:
        if await users_collection.find_one({"username": user_update.username, "_id": {"$ne": current_user["_id"]}}):
            raise HTTPException(status_code=400, detail="Username already taken")
        update_data["username"] = user_update.username

    # Email update — check karo koi aur use nahi kar raha
    if user_update.email:
        if await users_collection.find_one({"email": user_update.email, "_id": {"$ne": current_user["_id"]}}):
            raise HTTPException(status_code=400, detail="Email already taken")
        update_data["email"] = user_update.email

    # Password update
    if user_update.password:
        update_data["password"] = hash_password(user_update.password)

    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided to update")

    # Agar username badla hai to naya token bhi banao (warna purana token invalid ho jayega)
    new_username = update_data.get("username", current_user["username"])
    new_token = create_access_token(data={"sub": new_username})
    update_data["access_token"] = new_token

    await users_collection.update_one({"_id": current_user["_id"]}, {"$set": update_data})
    updated_user = await users_collection.find_one({"_id": current_user["_id"]})
    return {"username": updated_user["username"], "email": updated_user.get("email"), "created_at": updated_user["created_at"]}

@app.delete("/users/me")
async def delete_my_account(current_user: dict = Depends(get_current_user)):
    await users_collection.delete_one({"_id": current_user["_id"]})
    return {"message": "Account deleted successfully"}


@app.post("/smart-login", response_model=SmartLoginResponse)
async def smart_login(data: SmartLoginRequest):
    """
    Smart Login/Register Endpoint:

    - **Agar email already registered hai**: seedha login hoga apni purani email + password se.
      (Username dene ki zaroorat nahi)
    - **Agar email nai hai (naya user)**: username bhi dena hoga — account banake login ho jayega.
    """
    # Step 1: Check karo — kya ye email already registered hai?
    existing_user = await users_collection.find_one({"email": data.email})

    if existing_user:
        # ── PURANA USER: seedha login karo ──
        if not verify_password(data.password, existing_user["password"]):
            raise HTTPException(
                status_code=401,
                detail="Password galat hai. Apna sahi password enter karein."
            )

        # Token banao aur save karo
        token = create_access_token(data={"sub": existing_user["username"]})
        await users_collection.update_one(
            {"_id": existing_user["_id"]},
            {"$set": {"access_token": token}}
        )

        return {"access_token": token, "token_type": "bearer", "is_new_user": False}

    else:
        # ── NAYA USER: register karke login karo ──
        if not data.username:
            raise HTTPException(
                status_code=400,
                detail="Aap pehle registered nahi hain. Naya account banane ke liye 'username' bhi zaroor dein."
            )

        # Username already exist to nahi karta?
        if await users_collection.find_one({"username": data.username}):
            raise HTTPException(
                status_code=400,
                detail="Ye username pehle se kisi ne le rakha hai. Koi aur username choose karein."
            )

        # Naya user document banao
        user_doc = {
            "username": data.username,
            "email": data.email,
            "password": hash_password(data.password),
            "role": "user",  # Default role
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }
        await users_collection.insert_one(user_doc)

        # Token banao aur save karo
        token = create_access_token(data={"sub": data.username})
        await users_collection.update_one(
            {"email": data.email},
            {"$set": {"access_token": token}}
        )

        return {"access_token": token, "token_type": "bearer", "is_new_user": True}


# ==========================================
# 3. FORGOT PASSWORD (OTP Flow)
# ==========================================
@app.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Step 1: User apni email dega, OTP us email pe jayega."""
    # Check if user exists with this email
    user = await users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="No account found with this email")

    # Generate 6-digit OTP
    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)

    # Save OTP in database
    await users_collection.update_one(
        {"email": request.email},
        {"$set": {"reset_otp": otp, "otp_expiry": otp_expiry}}
    )

    # Send OTP via email
    email_sent = send_otp_email(request.email, otp)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Could not send OTP email. Check server email configuration.")

    return {"message": f"OTP sent to {request.email}. Valid for 10 minutes."}


@app.post("/reset-password")
async def reset_password(request: VerifyOTPRequest):
    """Step 2: User email + OTP + naya password dega, password change ho jayega."""
    # Find user by email
    user = await users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="No account found with this email")

    # Check OTP exists
    if not user.get("reset_otp"):
        raise HTTPException(status_code=400, detail="No OTP requested. Please use /forgot-password first.")

    # Check OTP expiry
    otp_expiry = user.get("otp_expiry")
    if otp_expiry and datetime.datetime.now(datetime.timezone.utc) > otp_expiry:
        raise HTTPException(status_code=400, detail="OTP has expired. Please request a new one.")

    # Check OTP match
    if user.get("reset_otp") != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Update password and remove OTP from database
    await users_collection.update_one(
        {"email": request.email},
        {
            "$set": {"password": hash_password(request.new_password)},
            "$unset": {"reset_otp": "", "otp_expiry": ""}
        }
    )

    return {"message": "Password reset successfully! Please login with your new password."}


# ==========================================
# 4. ADMIN ENDPOINTS (Admin Only Access)
# ==========================================

@app.get("/admin/stats")
async def get_stats(admin: dict = Depends(get_admin_user)):
    """Total users aur admins ki count dikhao."""
    total_users = await users_collection.count_documents({"role": "user"})
    total_admins = await users_collection.count_documents({"role": "admin"})
    total_all = await users_collection.count_documents({})
    return {
        "total_accounts": total_all,
        "total_users": total_users,
        "total_admins": total_admins
    }

@app.get("/admin/users", response_model=list[AdminUserResponse])
async def get_all_users(admin: dict = Depends(get_admin_user)):
    """Saare registered users ki list (Admin only)."""
    users = []
    async for user in users_collection.find({}, {"password": 0, "access_token": 0, "reset_otp": 0, "otp_expiry": 0}):
        users.append({
            "username": user["username"],
            "email": user.get("email"),
            "role": user.get("role", "user"),
            "created_at": user["created_at"]
        })
    return users

@app.put("/admin/users/{username}/role")
async def update_user_role(username: str, role_data: RoleUpdateRequest, admin: dict = Depends(get_admin_user)):
    """Kisi bhi user ka role change karo — 'admin' ya 'user' (Admin only)."""
    if role_data.role not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Invalid role. Sirf 'admin' ya 'user' allowed hai.")

    user = await users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{username}' nahi mila.")

    # Admin apna role khud nahi badal sakta
    if user["username"] == admin["username"]:
        raise HTTPException(status_code=400, detail="Aap apna khud ka role nahi badal sakte.")

    await users_collection.update_one({"username": username}, {"$set": {"role": role_data.role}})
    return {"message": f"User '{username}' ka role successfully '{role_data.role}' kar diya gaya."}

@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str, admin: dict = Depends(get_admin_user)):
    """Kisi bhi user ka account delete karo (Admin only)."""
    user = await users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{username}' nahi mila.")

    # Admin apna account khud delete nahi kar sakta
    if user["username"] == admin["username"]:
        raise HTTPException(status_code=400, detail="Aap apna khud ka account delete nahi kar sakte.")

    await users_collection.delete_one({"username": username})
    return {"message": f"User '{username}' ka account successfully delete kar diya gaya."}
