import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
from bson import ObjectId

# Import functions and configurations from other files
from database import users_collection, create_db_indexes
from security import hash_password, verify_password, create_access_token, verify_token
from schemas import UserCreate, UserUpdate, UserResponse, Token, UserLogin
from middleware import setup_middlewares

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
    # Step 1: Check if the username already exists in the database
    if await users_collection.find_one({"username": user_data.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
        
    # Step 2: Prepare user data and encrypt the password
    user_doc = {
        "username": user_data.username,
        "password": hash_password(user_data.password),
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }
    
    # Step 3: Save the new user in the database
    await users_collection.insert_one(user_doc)
    
    # Step 4: Return success response
    return {"username": user_doc["username"], "created_at": user_doc["created_at"]}

@app.post("/login", response_model=Token)
async def login(login_data: UserLogin):
    # Step 1: Find the user in the database by username OR email
    user = await users_collection.find_one({
        "$or": [
            {"username": login_data.username_or_email},
            {"email": login_data.username_or_email}
        ]
    })
    
    # Step 2: If user is not found or password is wrong, show an error
    if not user or not verify_password(login_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect username/email or password")
        
    # Step 3: If everything is correct, create a new login token
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
