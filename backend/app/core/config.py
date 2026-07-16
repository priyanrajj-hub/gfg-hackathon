import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql://postgres:postgres@db:5432/sysiege"
    )
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me-in-prod")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "gemini")  # disclosed in README
    AI_MODEL: str = os.getenv("AI_MODEL", "gemini-2.0-flash")
    AI_API_KEY: str = os.getenv("AI_API_KEY", "")

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
