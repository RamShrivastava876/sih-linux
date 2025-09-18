import os
from functools import lru_cache

# Pydantic v2 moved BaseSettings to pydantic-settings. Support both.
try:  # v2
    from pydantic_settings import BaseSettings
    from pydantic import Field
except ImportError:  # fallback for pydantic v1
    from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    api_key: str | None = Field(default=None, env="CERTIWIPE_API_KEY")
    carbon_intensity: float = Field(default=0.475, env="CERTIWIPE_CARBON_INTENSITY")
    windows_full_raw_enable: bool = Field(default=False, env="CERTIWIPE_WINDOWS_RAW_FULL")
    rate_limit_per_minute: int = Field(default=60, env="CERTIWIPE_RATE_LIMIT")
    audit_enabled: bool = Field(default=True, env="CERTIWIPE_AUDIT")
    log_json: bool = Field(default=True, env="CERTIWIPE_LOG_JSON")

    class Config:
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = 'utf-8'

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
