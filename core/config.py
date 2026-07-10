"""Configuration management for Security Suite."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="SECSUITE_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # General
    app_name: str = "Security Suite"
    debug: bool = False
    data_dir: Path = Field(default=Path.home() / ".secsuite")
    seclists_path: Path | None = None

    # API Keys (optional)
    shodan_api_key: str | None = None
    virustotal_api_key: str | None = None
    hunter_api_key: str | None = None

    # AI Integration (optional)
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # Network settings
    request_timeout: int = 30
    max_concurrent_requests: int = 10
    user_agent: str = "SecuritySuite/0.1.0 (https://github.com/security-suite)"

    # Rate limiting
    requests_per_second: float = 5.0

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
