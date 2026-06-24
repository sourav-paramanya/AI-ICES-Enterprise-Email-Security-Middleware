"""Authentication and authorization endpoints."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from apps.governance_api.dependencies import get_db
from shared.database.models.users import User
from shared.schemas.governance import LoginRequest, TokenResponse
from shared.security.jwt import JWTProvider

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
jwt_provider = JWTProvider()


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and get JWT token",
)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(
        (User.username == request.username) | (User.email == request.username),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not pwd_context.verify(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    if user.is_locked:
        raise HTTPException(status_code=403, detail="Account is locked")

    # Update login metadata
    user.last_login_at = datetime.now(timezone.utc)
    user.failed_login_attempts = 0
    await db.flush()

    # Generate token
    token_response = jwt_provider.create_access_token(
        subject=str(user.id),
        role=user.role,
        permissions=user.permissions or [],
        extra_claims={
            "email": user.email,
            "username": user.username,
        },
    )

    return token_response


@router.post(
    "/refresh",
    summary="Refresh access token",
)
async def refresh_token(refresh_token: str, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt_provider.decode_token(refresh_token)
        if payload.exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Refresh token expired")

        stmt = select(User).where(User.id == payload.sub)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")

        token_response = jwt_provider.create_access_token(
            subject=str(user.id),
            role=user.role,
            permissions=user.permissions or [],
        )
        return token_response

    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
