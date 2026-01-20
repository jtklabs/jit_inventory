"""
Application settings using Pydantic.
"""
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = "postgresql://inventory:inventory_pass@localhost:5432/inventory"

    # Credential management
    credential_backend: Literal["local", "aws"] = "local"
    credential_path: str = "data/credentials"

    # AWS (for production)
    aws_region: str = "us-east-1"
    aws_secret_prefix: str = "jt-inventory/"

    # SNMP defaults
    snmp_timeout: int = 5
    snmp_retries: int = 2
    snmp_port: int = 161

    # Logging
    log_level: str = "INFO"

    # Scheduled rescanning
    rescan_enabled: bool = False
    rescan_interval_hours: int = 24  # How often to rescan all devices
    rescan_max_concurrent: int = 5  # Max concurrent rescans

    # Nautobot integration
    nautobot_url: str | None = None
    nautobot_token: str | None = None
    nautobot_verify_ssl: bool = True
    nautobot_tag_name: str = "Nova Inventory"

    # Authentication
    auth_enabled: bool = True
    auth_username: str = "admin"
    # Password can be plaintext or a werkzeug hash (pbkdf2:sha256:...)
    # Generate hash with:
    #   python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password', method='pbkdf2:sha256'))"
    # Note: In docker-compose .env files, escape $ as $$ (e.g., pbkdf2:sha256:...$$salt$$hash)
    auth_password_hash: str = "admin"  # Default plaintext for dev, use hash in production
    secret_key: str = "change-this-secret-key-in-production"
    session_lifetime_hours: int = 24


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
