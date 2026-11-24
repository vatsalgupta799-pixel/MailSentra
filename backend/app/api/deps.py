"""API dependencies for database sessions and authentication/RBAC."""

from typing import Generator, List, Optional
from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.api_key import verify_api_key
from app.core.config import settings
from app.core.logging import logger
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User, UserRole
from app.schemas.user import IngestionActor, TokenData, UserResponse

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
)

oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False,
)


async def get_current_user_optional(
    db: AsyncSession = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),
) -> Optional[User]:
    """Retrieves current user if authenticated, or None if no token provided."""
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        email: str = payload.get("sub")
        if not email:
            return None
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        return user if user and user.is_active else None
    except Exception:
        return None


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
) -> User:
    """Validates the JWT access token and retrieves the current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        email: str = payload.get("sub")
        role: str = payload.get("role")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email, role=role)
    except JWTError:
        raise credentials_exception

    stmt = select(User).where(User.email == token_data.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account",
        )
    return user


def require_roles(allowed_roles: List[UserRole]):
    """Enforces Role-Based Access Control on endpoint execution."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles and current_user.role != UserRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for role '{current_user.role}'",
            )
        return current_user
    return role_checker


async def get_ingestion_actor(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> IngestionActor:
    """Authenticates ingestion collectors (via API Key) or human operators (via JWT).

    Supports:
    1. Header `X-API-Key: <key>`
    2. Header `Authorization: ApiKey <key>`
    3. Header `Authorization: Bearer <token>` (handles both API Key and JWT tokens)
    4. Enforces authentication strictly when settings.is_ingestion_auth_enforced is True.
    """
    client_ip = request.client.host if request.client else "unknown"

    # 1. Check X-API-Key Header
    if x_api_key:
        if not settings.INGESTION_API_KEY:
            logger.warning(f"Ingestion auth rejected: API key provided from {client_ip} but INGESTION_API_KEY is not configured.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key credentials",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        if verify_api_key(x_api_key, settings.INGESTION_API_KEY):
            return IngestionActor(identity="collector:api_key", role="collector", is_api_key=True)
        else:
            logger.warning(f"Ingestion auth rejected: Invalid API key provided from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key credentials",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    # 2. Check Authorization Header
    if authorization:
        clean_auth = authorization.strip()
        if " " not in clean_auth:
            logger.warning(f"Ingestion auth rejected: Malformed Authorization header from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Authorization header format",
                headers={"WWW-Authenticate": 'ApiKey, Bearer'},
            )

        scheme, token = clean_auth.split(" ", 1)
        scheme_lower = scheme.lower()
        token = token.strip()

        if not token:
            logger.warning(f"Ingestion auth rejected: Empty token in Authorization header from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Empty credential token in Authorization header",
                headers={"WWW-Authenticate": 'ApiKey, Bearer'},
            )

        if scheme_lower == "apikey":
            if not settings.INGESTION_API_KEY or not verify_api_key(token, settings.INGESTION_API_KEY):
                logger.warning(f"Ingestion auth rejected: Invalid ApiKey token from {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API Key credentials",
                    headers={"WWW-Authenticate": "ApiKey"},
                )
            return IngestionActor(identity="collector:api_key", role="collector", is_api_key=True)

        elif scheme_lower == "bearer":
            # Check if Bearer token matches configured API key (collector bearer mode)
            if settings.INGESTION_API_KEY and verify_api_key(token, settings.INGESTION_API_KEY):
                return IngestionActor(identity="collector:api_key", role="collector", is_api_key=True)

            # Otherwise, validate as JWT access token
            try:
                payload = decode_access_token(token)
                email: str = payload.get("sub")
                if not email:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid JWT credentials: missing subject",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                stmt = select(User).where(User.email == email)
                result = await db.execute(stmt)
                user = result.scalar_one_or_none()
                if not user or not user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User account inactive or not found",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                return IngestionActor(
                    identity=user.email,
                    role=user.role.value,
                    is_api_key=False,
                    user=UserResponse.model_validate(user),
                )
            except HTTPException:
                raise
            except Exception:
                logger.warning(f"Ingestion auth rejected: JWT decode/validation failure from {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Bearer authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        else:
            logger.warning(f"Ingestion auth rejected: Unsupported authorization scheme '{scheme}' from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unsupported authorization scheme '{scheme}'. Expected 'Bearer' or 'ApiKey'.",
                headers={"WWW-Authenticate": 'ApiKey, Bearer'},
            )

    # 3. Neither Header Provided
    if settings.is_ingestion_auth_enforced:
        logger.warning(f"Ingestion auth rejected: Missing credentials from {client_ip} under enforced auth policy")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required. Please provide a valid API Key (X-API-Key) or Bearer Token.",
            headers={"WWW-Authenticate": 'ApiKey realm="MailSentra Ingestion", Bearer'},
        )

    # Fallback only when auth is explicitly not enforced (development mode)
    return IngestionActor(identity="dev:unauthenticated", role="collector", is_api_key=False)


async def get_scan_reader(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> IngestionActor:
    """Authenticates human SOC analysts or administrators for reading scan telemetry.

    Explicitly rejects ingestion API keys with HTTP 403 Forbidden to enforce separation of duties.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Reject if client attempts to use an Ingestion API Key for read telemetry
    if x_api_key:
        logger.warning(f"Scan read access denied: API Key provided from {client_ip} (write-only credential)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API keys are restricted to write-only email ingestion. Accessing scan telemetry requires interactive analyst credentials.",
        )

    if authorization:
        clean_auth = authorization.strip()
        if " " not in clean_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Authorization header format",
                headers={"WWW-Authenticate": "Bearer"},
            )
        scheme, token = clean_auth.split(" ", 1)
        scheme_lower = scheme.lower()
        token = token.strip()

        if scheme_lower == "apikey":
            logger.warning(f"Scan read access denied: ApiKey provided from {client_ip} (write-only credential)")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API keys are restricted to write-only email ingestion. Accessing scan telemetry requires interactive analyst credentials.",
            )

        if scheme_lower == "bearer":
            # If Bearer matches the ingestion API key, reject with 403
            if settings.INGESTION_API_KEY and verify_api_key(token, settings.INGESTION_API_KEY):
                logger.warning(f"Scan read access denied: Ingestion API key Bearer token provided from {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="API keys are restricted to write-only email ingestion. Accessing scan telemetry requires interactive analyst credentials.",
                )

            # Validate as JWT access token
            try:
                payload = decode_access_token(token)
                email: str = payload.get("sub")
                if not email:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid JWT credentials: missing subject",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                stmt = select(User).where(User.email == email)
                result = await db.execute(stmt)
                user = result.scalar_one_or_none()
                if not user or not user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User account inactive or not found",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                # Enforce role authorization: only SOC analysts, admins, and auditors can read scans
                if user.role not in [UserRole.SUPER_ADMIN, UserRole.SOC_ANALYST, UserRole.AUDITOR]:
                    logger.warning(f"Scan read access denied: User '{user.email}' with role '{user.role}' is not authorized to read scans")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"User role '{user.role.value}' is not authorized to view scan telemetry.",
                    )
                return IngestionActor(
                    identity=user.email,
                    role=user.role.value,
                    is_api_key=False,
                    user=UserResponse.model_validate(user),
                )
            except HTTPException:
                raise
            except Exception:
                logger.warning(f"Scan read auth rejected: JWT decode/validation failure from {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Bearer authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported authorization scheme '{scheme}'. Expected 'Bearer'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Neither header provided
    if settings.is_ingestion_auth_enforced:
        logger.warning(f"Scan read auth rejected: Missing credentials from {client_ip} under enforced auth policy")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required. Please provide a valid Bearer Token.",
            headers={"WWW-Authenticate": 'Bearer realm="MailSentra Telemetry"'},
        )

    return IngestionActor(identity="dev:unauthenticated", role="collector", is_api_key=False)
