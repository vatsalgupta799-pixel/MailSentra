"""Application configuration management using Pydantic Settings."""

from typing import List, Optional, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "MailSentra Threat Detection Platform"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Security
    SECRET_KEY: str = "dev_secret_key_change_in_production_mailsentra_secops_platform"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./mailsentra.db"

    # CORS
    ALLOWED_ORIGINS: Union[str, List[str]] = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def cors_origins(self) -> List[str]:
        if isinstance(self.ALLOWED_ORIGINS, str):
            return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]
        return self.ALLOWED_ORIGINS

    # Operational Parameters
    MAX_EMAIL_SIZE_BYTES: int = 15 * 1024 * 1024  # 15MB
    MAX_MIME_PARTS: int = 250
    MAX_EXTRACTED_URLS: int = 500
    MAX_ATTACHMENTS: int = 50
    MAX_ATTACHMENT_SIZE_BYTES: int = 10 * 1024 * 1024  # 10MB per attachment
    MAX_RECIPIENT_ADDRESSES: int = 100
    MAX_RECEIVED_HOPS: int = 100
    DEFAULT_RISK_THRESHOLD_SUSPICIOUS: int = 30
    DEFAULT_RISK_THRESHOLD_MALICIOUS: int = 70

    # Ingestion Access Control & API Key
    REQUIRE_INGESTION_AUTH: bool = False
    INGESTION_API_KEY: Optional[str] = None
    INGESTION_API_KEY_HEADER: str = "X-API-Key"

    # Initial Administrator Bootstrap (Optional for Production First-Run)
    INITIAL_ADMIN_EMAIL: Optional[str] = None
    INITIAL_ADMIN_PASSWORD: Optional[str] = None

    @property
    def is_ingestion_auth_enforced(self) -> bool:
        """Enforces authentication unconditionally in non-development environments,

        or when explicitly enabled via REQUIRE_INGESTION_AUTH.
        """
        if self.ENVIRONMENT.lower().strip() != "development":
            return True
        return self.REQUIRE_INGESTION_AUTH

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
