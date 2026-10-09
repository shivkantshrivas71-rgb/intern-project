import asyncio
import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

async def main():
    try:
        client = AsyncIOMotorClient(os.getenv('MONGO_URI'), serverSelectionTimeoutMS=5000)
        info = await client.server_info()
        print("Connected:", info)
    except Exception as e:
        print("Error:", e)

asyncio.run(main())
