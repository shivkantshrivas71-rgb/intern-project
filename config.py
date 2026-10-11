"""
config.py — Centralized Configuration Loader
All environment variables for the Master API are loaded here.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application-wide settings — loaded from the .env file."""

    # ── MongoDB ──────────────────────────────────────────────
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    DB_NAME: str = os.getenv("DB_NAME", "fastapi_auth_db")

    # ── JWT ──────────────────────────────────────────────────
    JWT_SECRET_KEY: str = os.getenv(
        "JWT_SECRET_KEY", "fallback-secret-key-do-not-use-in-prod"
    )
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRATION_MINUTES: int = int(os.getenv("JWT_EXPIRATION_MINUTES", "1440"))

    # ── Email / SMTP ─────────────────────────────────────────
    EMAIL_HOST: str = os.getenv("EMAIL_HOST", "smtp.gmail.com")
    EMAIL_PORT: int = int(os.getenv("EMAIL_PORT", "587"))
    EMAIL_USER: str = os.getenv("EMAIL_USER", "")
    EMAIL_PASSWORD: str = os.getenv("EMAIL_PASSWORD", "")

    # ── App ──────────────────────────────────────────────────
    APP_TITLE: str = os.getenv("APP_TITLE", "Master API Gateway")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
    APP_DESCRIPTION: str = os.getenv(
        "APP_DESCRIPTION",
        "Production-ready FastAPI + MongoDB Master API with modular architecture.",
    )
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"


# Singleton instance — used throughout the entire project
settings = Settings()
