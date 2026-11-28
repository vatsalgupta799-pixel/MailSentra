"""MailSentra FastAPI ASGI Application Entrypoint."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import logger, setup_logging
from app.core.security import get_password_hash
from app.db.base import Base
from app.db.session import async_engine, AsyncSessionLocal
from app.models.user import User, UserRole
from sqlalchemy import select


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager: database schema verification, seed creation, and security checks."""
    setup_logging()
    logger.info("Initializing MailSentra platform foundation...")

    # Strict Startup Configuration & Cryptographic Key Validation
    env_clean = settings.ENVIRONMENT.lower().strip()
    if env_clean == "production":
        insecure_keys = [
            "dev_secret_key_change_in_production_mailsentra_secops_platform",
            "replace_with_a_secure_random_string_in_production_environment",
            "changeme",
            "secret",
            "password",
        ]
        if settings.SECRET_KEY in insecure_keys or len(settings.SECRET_KEY) < 32:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Default, insecure, or insufficient length SECRET_KEY detected in production. "
                "You must configure a unique, high-entropy SECRET_KEY of at least 32 characters via environment variables."
            )
        if settings.is_ingestion_auth_enforced and not settings.INGESTION_API_KEY:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Ingestion authentication is enforced in production, "
                "but INGESTION_API_KEY is not configured. Set INGESTION_API_KEY via environment variables."
            )
        if settings.INITIAL_ADMIN_PASSWORD:
            if settings.INITIAL_ADMIN_PASSWORD in ["MailSentraAdmin2026!", "Admin2026!", "password", "Password123!"]:
                raise RuntimeError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: Known default password detected for INITIAL_ADMIN_PASSWORD in production. "
                    "You must supply a strong, unique initial administrator password (minimum 12 characters)."
                )
            if len(settings.INITIAL_ADMIN_PASSWORD) < 12:
                raise RuntimeError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: INITIAL_ADMIN_PASSWORD in production must be at least 12 characters."
                )

    # Create tables if they do not exist (for SQLite dev mode)
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Ensure schema migrations apply cleanly to existing SQLite tables
        from sqlalchemy import text
        for col_def in [
            "ALTER TABLE scan_incidents ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default'",
            "ALTER TABLE scan_incidents ADD COLUMN created_by_user_id INTEGER",
        ]:
            try:
                await conn.execute(text(col_def))
            except Exception:
                pass
    logger.info("Database schema initialized.")

    # Administrator Account Provisioning Logic
    async with AsyncSessionLocal() as session:
        if env_clean == "development":
            # Seed default development admin user ONLY in development environment
            stmt = select(User).where(User.email == "admin@mailsentra.local")
            result = await session.execute(stmt)
            admin = result.scalar_one_or_none()
            if not admin:
                default_admin = User(
                    email="admin@mailsentra.local",
                    full_name="MailSentra System Administrator",
                    hashed_password=get_password_hash("MailSentraAdmin2026!"),
                    role=UserRole.SUPER_ADMIN,
                    is_active=True,
                )
                session.add(default_admin)
                await session.commit()
                logger.info("Development environment: Provisioned development administrator (admin@mailsentra.local).")
            elif not admin.is_active:
                admin.is_active = True
                await session.commit()
                logger.info("Development environment: Re-activated development administrator (admin@mailsentra.local).")
        else:
            # Production: deactivate legacy development default admin if it was accidentally copied into database
            legacy_stmt = select(User).where(User.email == "admin@mailsentra.local")
            legacy_result = await session.execute(legacy_stmt)
            legacy_admin = legacy_result.scalar_one_or_none()
            if legacy_admin and legacy_admin.is_active:
                legacy_admin.is_active = False
                await session.commit()
                logger.warning("Production environment: Deactivated insecure default development admin account.")

            # Production: Provision initial administrator from environment variables if specified
            if settings.INITIAL_ADMIN_EMAIL and settings.INITIAL_ADMIN_PASSWORD:
                stmt_init = select(User).where(User.email == settings.INITIAL_ADMIN_EMAIL)
                res_init = await session.execute(stmt_init)
                existing_init = res_init.scalar_one_or_none()
                if not existing_init:
                    init_admin = User(
                        email=settings.INITIAL_ADMIN_EMAIL,
                        full_name="Initial MailSentra Administrator",
                        hashed_password=get_password_hash(settings.INITIAL_ADMIN_PASSWORD),
                        role=UserRole.SUPER_ADMIN,
                        is_active=True,
                    )
                    session.add(init_admin)
                    await session.commit()
                    logger.info(f"Production environment: Initial administrator provisioned for '{settings.INITIAL_ADMIN_EMAIL}'.")
            else:
                logger.info("Production environment: Default administrator seeding disabled. Use CLI utility to provision accounts.")

    # Initialize and verify Authentication Protocols subsystem (Step 3.7.4)
    try:
        from app.services.scan_service import scan_service
        if hasattr(scan_service, "auth_analyzer") and scan_service.auth_analyzer:
            logger.info(
                f"Authentication Protocols subsystem ready (local_authserv_id={settings.LOCAL_AUTHSERV_ID or '<unconfigured>'}, "
                f"dmarc_enforcement={settings.DMARC_POLICY_ENFORCEMENT_ENABLED})"
            )
    except Exception as e_init:
        logger.warning(f"Authentication Protocols subsystem startup verification warning: {e_init}")

    yield

    logger.info("Shutting down MailSentra engine...")
    # Clean up Authentication Protocols Subsystem resources (Step 3.7.4)
    try:
        from app.services.scan_service import scan_service
        if hasattr(scan_service, "shutdown"):
            logger.info("Shutting down ScanService and AuthProtocolsAnalyzer resources...")
            await scan_service.shutdown()
        elif hasattr(scan_service, "auth_analyzer") and scan_service.auth_analyzer:
            logger.info("Shutting down AuthProtocolsAnalyzer directly...")
            await scan_service.auth_analyzer.shutdown()
    except Exception as e_shut:
        logger.error(f"Error during authentication subsystem shutdown: {e_shut}", exc_info=True)
    finally:
        await async_engine.dispose()


is_dev_env = settings.ENVIRONMENT.lower().strip() == "development"

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Email Security and Threat Detection Platform API",
    version="1.0.0-phase2",
    openapi_url=f"{settings.API_V1_STR}/openapi.json" if is_dev_env else None,
    docs_url="/docs" if is_dev_env else None,
    redoc_url="/redoc" if is_dev_env else None,
    lifespan=lifespan,
)

# Cross-Origin Resource Sharing (CORS) Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforces essential defensive HTTP response headers."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# Mount API Routers
app.include_router(api_router, prefix=settings.API_V1_STR)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
