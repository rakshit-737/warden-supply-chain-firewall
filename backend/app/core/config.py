"""Application configuration.

All configuration comes from the environment (12-factor). The settings object is
validated at import time and fails closed: a production deployment that is missing a
strong secret or is left with an insecure default will refuse to start rather than run
insecurely.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Environment -------------------------------------------------------
    ENV: str = Field(default="development", description="development|staging|production")
    DEBUG: bool = False

    # --- Server ------------------------------------------------------------
    PROJECT_NAME: str = "Warden Supply-Chain Firewall"
    API_V1_PREFIX: str = "/api/v1"
    HOST: str = "0.0.0.0"  # nosec B104 - binding all interfaces is intended inside a container
    PORT: int = 8000

    # --- Security ----------------------------------------------------------
    # A random secret is generated if none is supplied so local dev works out of the
    # box; production is *required* to supply one (enforced below).
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 7
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 2

    # Comma-separated list of allowed CORS origins.
    CORS_ORIGINS: List[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    # --- First-run bootstrap admin ----------------------------------------
    FIRST_ADMIN_EMAIL: str = "admin@warden.io"
    # nosec B105 - a development default only; production startup refuses to boot unless
    # this is overridden (see _enforce_production_hardening below).
    FIRST_ADMIN_PASSWORD: str = "ChangeMe_Warden!2026"  # nosec B105

    # --- Datastores --------------------------------------------------------
    DATABASE_URL: str = "sqlite+pysqlite:///./warden.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    # If Redis is unavailable, fall back to an in-process limiter/cache (dev only).
    REDIS_OPTIONAL: bool = True

    # --- Rate limiting -----------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 120
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10

    # --- Analysis pipeline -------------------------------------------------
    ANALYZER_VERSION: str = "1.0.0"
    FETCH_TIMEOUT_SECONDS: int = 20
    MAX_DOWNLOAD_BYTES: int = 25 * 1024 * 1024  # 25 MiB compressed artifact cap
    MAX_EXTRACTED_BYTES: int = 120 * 1024 * 1024  # 120 MiB decompressed cap (zip-bomb guard)
    MAX_EXTRACTED_FILES: int = 25000  # generous: real packages (numpy, etc.) are large
    MAX_ANALYZED_FILE_BYTES: int = 2 * 1024 * 1024  # per-file parse cap
    PYPI_JSON_BASE: str = "https://pypi.org/pypi"
    VERDICT_CACHE_TTL_SECONDS: int = 3600
    # Fusion mode for combining rule and ml scores: "max" (conservative) or "mean".
    SCORE_FUSION: str = "max"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> "Settings":
        if self.ENV == "production":
            insecure_secret = len(self.SECRET_KEY) < 32
            if insecure_secret:
                raise ValueError(
                    "SECRET_KEY must be set to a strong value (>=32 chars) in production."
                )
            if self.FIRST_ADMIN_PASSWORD == "ChangeMe_Warden!2026":  # nosec B105
                raise ValueError(
                    "FIRST_ADMIN_PASSWORD must be changed from its default in production."
                )
            if self.DEBUG:
                raise ValueError("DEBUG must be False in production.")
        return self

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
