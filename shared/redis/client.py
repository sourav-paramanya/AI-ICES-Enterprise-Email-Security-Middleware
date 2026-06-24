import logging
from functools import lru_cache
from typing import Any, Optional

from redis.asyncio import Redis as AsyncRedis

from shared.config.settings import get_settings

logger = logging.getLogger(__name__)


class RedisClient:
    def __init__(self) -> None:
        self._client: Optional[AsyncRedis] = None

    async def connect(self) -> None:
        settings = get_settings()
        self._client = AsyncRedis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        await self._client.ping()
        logger.info(
            "Connected to Redis at %s:%s",
            settings.REDIS_HOST,
            settings.REDIS_PORT,
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Disconnected from Redis")

    @property
    def client(self) -> AsyncRedis:
        if self._client is None:
            raise RuntimeError("Redis client not initialized. Call connect() first.")
        return self._client

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        return await self.client.set(key, value, ex=ttl)

    async def get(self, key: str) -> Optional[str]:
        return await self.client.get(key)

    async def delete(self, key: str) -> bool:
        return await self.client.delete(key) > 0

    async def exists(self, key: str) -> bool:
        return await self.client.exists(key) > 0

    @property
    def is_connected(self) -> bool:
        if self._client is None:
            return False
        try:
            return self._client.is_connected()
        except Exception:
            return False


@lru_cache
def get_redis_client() -> RedisClient:
    return RedisClient()
