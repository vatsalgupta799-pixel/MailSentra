"""Authentication and identity endpoints."""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter
from app.core.security import create_access_token, verify_password
from app.models.user import User
from app.schemas.user import Token, UserResponse

router = APIRouter()


@router.post("/login", response_model=Token, summary="OAuth2 Password Login")
async def login_for_access_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """Authenticates user credentials and returns a signed JWT access token."""
    login_rate_limiter.check_rate_limit(request)

    # In production, block attempts to use known default development passwords
    if settings.ENVIRONMENT.lower().strip() == "production" and form_data.password in [
        "MailSentraAdmin2026!",
        "Admin2026!",
        "password",
        "Password123!",
    ]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    stmt = select(User).where(User.email == form_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account",
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user.email,
        role=user.role.value,
        expires_delta=access_token_expires,
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        role=user.role.value,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse, summary="Current User Profile")
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """Returns the authenticated user's profile and RBAC role."""
    return current_user
