import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()
uri = os.getenv("MONGO_URI")
print("URI:", uri)

async def test():
    try:
        client = AsyncIOMotorClient(uri)
        await client.admin.command('ping')
        print("Success!")
    except Exception as e:
        print("Error:", e)

asyncio.run(test())
