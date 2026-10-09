from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
import os

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to every response to prevent
    attacks like Clickjacking, XSS, and MIME-sniffing.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Only allow resources to be loaded from same origin by default
        # (Excluded for docs so Swagger UI can load JS/CSS from CDNs)
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
            response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

def setup_middlewares(app):
    # Restricted CORS: Allow only specific frontend domain instead of "*"
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[FRONTEND_URL], # Secure CORS
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # Add custom security headers
    app.add_middleware(SecurityHeadersMiddleware)
