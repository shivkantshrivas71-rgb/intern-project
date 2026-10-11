"""
main.py — Master API Gateway (Central Entry Point)

This file is the central hub of the entire application.
All modules are registered here via APIRouter.

Architecture:
    main.py (Gateway)
        ├── modules/users/routes.py   → /register, /login, /users/*, /admin/*
        └── modules/agents/routes.py  → /agents/*

Startup:
    uvicorn main:app --reload
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from config import settings
from database import create_db_indexes
from middleware import setup_middlewares

# ── Module Routers ────────────────────────────────────────────────────────────
from modules.users.routes import router as users_router
from modules.agents.routes import router as agents_router


# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION LIFESPAN (startup / shutdown hooks)
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager.

    startup  → Verify MongoDB connection and create all required indexes
    shutdown → Resources are released gracefully
    """
    # ── STARTUP ──────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  {settings.APP_TITLE} v{settings.APP_VERSION}")
    print(f"  Starting up... connecting to MongoDB")
    print(f"{'='*60}\n")

    await create_db_indexes()

    print(f"\n[Gateway] All modules loaded. API is ready.\n")
    # ─────────────────────────────────────────────────────────

    yield  # Application runs here

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

# ── Middlewares ───────────────────────────────────────────────────────────────
setup_middlewares(app)

# ── Register Module Routers ───────────────────────────────────────────────────
app.include_router(users_router)    # /register, /login, /users/*, /admin/*
app.include_router(agents_router)   # /agents/*


# ─────────────────────────────────────────────────────────────────────────────
# ROOT HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"], summary="API health check")
async def root():
    """
    Master API Gateway root health check endpoint.
    If this response is received, the server is running correctly.
    """
    return JSONResponse(
        content={
            "status": "healthy",
            "app": settings.APP_TITLE,
            "version": settings.APP_VERSION,
            "documentation": {
                "swagger": "/docs",
                "redoc": "/redoc",
            },
            "modules": ["users", "agents"],
        }
    )


@app.get("/health", tags=["Health"], summary="Detailed health status")
async def health_check():
    """Return detailed health status including all registered module endpoints."""
    return {
        "status": "ok",
        "database": "mongodb",
        "modules": {
            "users": {
                "endpoints": [
                    "POST   /register",
                    "POST   /login",
                    "POST   /smart-login",
                    "GET    /users/me",
                    "PUT    /users/me",
                    "DELETE /users/me",
                    "POST   /forgot-password",
                    "POST   /reset-password",
                    "GET    /admin/stats",
                    "GET    /admin/users",
                    "PUT    /admin/users/{username}/role",
                    "DELETE /admin/users/{username}",
                ]
            },
            "agents": {
                "endpoints": [
                    "POST   /agents/",
                    "GET    /agents/",
                    "GET    /agents/{id}",
                    "PUT    /agents/{id}",
                    "DELETE /agents/{id}",
                    "PATCH  /agents/bulk/status",
                ]
            },
        },
    }
