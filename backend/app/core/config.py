"""Application configuration management using Pydantic Settings."""

import re
from typing import Any, List, Optional, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AUTHSERV_ID_PATTERN = re.compile(
    r"^(?=.{1,255}$)[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$"
)


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

    # Module 4: Authentication Protocols Operational Settings (Step 3.7.4)
    LOCAL_AUTHSERV_ID: Optional[str] = None
    DMARC_POLICY_ENFORCEMENT_ENABLED: bool = True

    @field_validator("LOCAL_AUTHSERV_ID", mode="before")
    @classmethod
    def _validate_local_authserv_id(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("LOCAL_AUTHSERV_ID must be a string or None.")
        if not value.strip():
            return None
        # Disallow control characters, whitespace, semicolons, quotes, colons, slashes
        if any(ord(c) < 33 or ord(c) > 126 or c in ';:"\'/\\[]()<>' for c in value):
            raise ValueError(
                f"LOCAL_AUTHSERV_ID contains disallowed whitespace, control characters, or delimiters: '{value}'"
            )
        clean_val = value.strip()
        if len(clean_val) > 255:
            raise ValueError(
                f"LOCAL_AUTHSERV_ID exceeds maximum RFC 8601 length of 255 characters (length={len(clean_val)})."
            )
        if not AUTHSERV_ID_PATTERN.match(clean_val):
            raise ValueError(
                f"LOCAL_AUTHSERV_ID must conform to RFC 8601 Section 2.5 FQDN/atom syntax: '{clean_val}'"
            )
        return clean_val

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
