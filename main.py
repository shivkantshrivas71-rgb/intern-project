import datetime
import random
import smtplib
import os
from email.mime.text import MIMEText
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
from bson import ObjectId
from dotenv import load_dotenv

load_dotenv()

# Import functions and configurations from other files
from database import users_collection, create_db_indexes
from security import hash_password, verify_password, create_access_token, verify_token
from schemas import UserCreate, UserUpdate, UserResponse, Token, UserLogin, ForgotPasswordRequest, VerifyOTPRequest
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


# ==========================================
# 2. USER ENDPOINTS (Register, Login, Update Profile)
# ==========================================
@app.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    # Step 1: Check if the username already exists
    if await users_collection.find_one({"username": user_data.username}):
        raise HTTPException(status_code=400, detail="Username already exists")

    # Step 2: Check if email already exists
    if await users_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
        
    # Step 3: Prepare user data and encrypt the password
    user_doc = {
        "username": user_data.username,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }
    
    # Step 4: Save the new user in the database
    await users_collection.insert_one(user_doc)
    
    # Step 5: Return success response
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
    if user_update.username:
        if await users_collection.find_one({"username": user_update.username, "_id": {"$ne": current_user["_id"]}}):
            raise HTTPException(status_code=400, detail="Username already taken")
        update_data["username"] = user_update.username
    if user_update.email:
        if await users_collection.find_one({"email": user_update.email, "_id": {"$ne": current_user["_id"]}}):
            raise HTTPException(status_code=400, detail="Email already taken")
        update_data["email"] = user_update.email
    if user_update.password:
        update_data["password"] = hash_password(user_update.password)
        
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided to update")
        
    await users_collection.update_one({"_id": current_user["_id"]}, {"$set": update_data})
    updated_user = await users_collection.find_one({"_id": current_user["_id"]})
    return {"username": updated_user["username"], "email": updated_user.get("email"), "created_at": updated_user["created_at"]}

@app.delete("/users/me")
async def delete_my_account(current_user: dict = Depends(get_current_user)):
    await users_collection.delete_one({"_id": current_user["_id"]})
    return {"message": "Account deleted successfully"}


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
