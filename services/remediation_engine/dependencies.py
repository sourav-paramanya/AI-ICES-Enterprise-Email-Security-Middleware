"""Remediation Engine dependency injection."""

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from shared.database.session import async_session_factory
from shared.rabbitmq import RabbitMQClient, get_rabbitmq_client
from shared.redis import RedisClient, get_redis_client

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


async def get_rabbitmq() -> AsyncGenerator[RabbitMQClient, None]:
    client = get_rabbitmq_client()
    if not client.is_connected:
        await client.connect()
    try:
        yield client
    finally:
        pass


async def get_redis() -> AsyncGenerator[RedisClient, None]:
    client = get_redis_client()
    if not client.is_connected:
        await client.connect()
    try:
        yield client
    finally:
        pass
