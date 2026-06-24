"""Governance API dependency injection."""

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from shared.database.session import async_session_factory
from shared.redis import RedisClient, get_redis_client
from shared.security.jwt import JWTProvider
from shared.security.rbac import RBACGuard, get_rbac_guard

logger = logging.getLogger(__name__)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_redis() -> AsyncGenerator[RedisClient, None]:
    client = get_redis_client()
    if not client.is_connected:
        await client.connect()
    try:
        yield client
    finally:
        pass


def get_jwt_provider() -> JWTProvider:
    return JWTProvider()


from fastapi import Header, HTTPException, Depends
from shared.security.rbac import Role, Permission, UserContext

async def get_current_user(
    authorization: str = Header(..., description="Bearer JWT token"),
    jwt_provider: JWTProvider = Depends(get_jwt_provider),
) -> UserContext:
    """Extract and validate JWT, returning a UserContext.
    Expected format: "Bearer <token>".
    """
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth header")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt_provider.decode_token(token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    # Convert role and permissions strings to Enum values; fall back to raw strings if conversion fails
    try:
        role_enum = Role(payload.role)
    except ValueError:
        role_enum = Role.SOC_ANALYST
    perm_enums = []
    for p in payload.permissions:
        try:
            perm_enums.append(Permission(p))
        except ValueError:
            continue
    return UserContext(
        user_id=payload.sub,
        username="",  # optional, not stored in token payload
        email="",
        role=role_enum,
        permissions=perm_enums,
        is_authenticated=True,
    )


def get_rbac() -> RBACGuard:
    return get_rbac_guard()
