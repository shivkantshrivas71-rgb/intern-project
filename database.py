"""
database.py — MongoDB Motor Driver Connection
Centralized database connection and collection references for the Master API.
"""
from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

# ── Client & DB ──────────────────────────────────────────────────────────────
client = AsyncIOMotorClient(settings.MONGO_URI)
db = client[settings.DB_NAME]

# ── Collections ──────────────────────────────────────────────────────────────
users_collection = db["users"]
agents_collection = db["agents"]


async def create_db_indexes() -> None:
    """
    Create all required database indexes on application startup.
    If an index already exists, MongoDB will silently ignore the duplicate request.
    """
    # Users
    await users_collection.create_index("username", unique=True)
    await users_collection.create_index("email", unique=True, sparse=True)

    # Agents
    await agents_collection.create_index("phone", unique=True)

    print(
        f"[DB] Connected to '{settings.DB_NAME}' — all indexes verified successfully."
    )
