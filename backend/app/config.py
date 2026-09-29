"""Centralised, typed configuration. Everything comes from env vars or .env."""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="WM_",
        case_sensitive=False,
        extra="ignore",
    )

    # Runtime
    env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "info"

    # Workbench auth
    jwt_secret: str = Field(default="dev-only-workbench-secret-change-me-please-32b", min_length=32)
    jwt_algorithm: str = "HS256"
    token_ttl_seconds: int = 3600

    # Lab gate
    lab_mode: int = 1

    # CORS
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"

    @field_validator("lab_mode")
    @classmethod
    def _warn_on_lab_mode(cls, v: int) -> int:
        # Loud warning at import time. This is the single most dangerous flag
        # in the entire codebase.
        if v == 1:
            print("\n" + "!" * 72)
            print("!!  WM_LAB_MODE=1 — intentionally vulnerable routes are ENABLED.")
            print("!!  Bind to 127.0.0.1 only. Never expose this process publicly.")
            print("!" * 72 + "\n")
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()