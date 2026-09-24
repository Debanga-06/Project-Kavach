"""
KavachAI Backend — FastAPI entrypoint.

Run locally:
    uvicorn app.main:app --reload --port 8000
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import Base, engine
from app.api import auth, urls, dashboard, emails

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-assisted cybersecurity platform: URL/email/file/secret threat detection.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://project-kavach-woad.vercel.app",
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Import models so they're registered on Base.metadata before create_all.
from app.models import user, scan, ai_report  # noqa: E402,F401

# NOTE: create_all is fine for local dev. Once the schema stabilizes, switch to
# Alembic migrations (planned in TRD Section 16/17) instead of relying on this.
Base.metadata.create_all(bind=engine)

app.include_router(auth.router, prefix=settings.API_V1_PREFIX + "/auth", tags=["auth"])
app.include_router(urls.router, prefix=settings.API_V1_PREFIX, tags=["scans"])
app.include_router(dashboard.router, prefix=settings.API_V1_PREFIX, tags=["dashboard"])
app.include_router(emails.router, prefix=settings.API_V1_PREFIX, tags=["scans"])


@app.get("/", tags=["health"])
def root():
    return {
        "service": settings.APP_NAME,
        "status": "ok",
        "env": settings.APP_ENV,
    }


@app.get("/api/v1/health", tags=["health"])
def health_check():
    """Basic health check. Will later report DB/Redis/ML worker status too."""
    return {"status": "healthy"}
