"""
Application configuration.
Loads settings from environment variables / .env file.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    APP_NAME: str = "KavachAI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Database (wired up in Step 2)
    DATABASE_URL: str = "postgresql+psycopg://kavachai:kavachai@localhost:5432/kavachai"

    # Redis (wired up later)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Auth (wired up in Step 2)
    JWT_SECRET_KEY: str = "change-me-in-env-file"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # AI explanation layer (PRD 6.6 / TRD 10) — optional. Empty string means
    # the AI service falls back to a template-based explanation, no crash.
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"
    AI_EXPLANATION_TIMEOUT_SECONDS: float = 8.0

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
