import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from shared.config.settings import get_settings

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck(BaseModel):
    status: HealthStatus
    version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    services: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def ok(cls, version: str, services: Optional[Dict[str, Any]] = None) -> "HealthCheck":
        return cls(
            status=HealthStatus.HEALTHY,
            version=version,
            services=services or {},
        )

    @classmethod
    def degraded(cls, version: str, services: Dict[str, Any]) -> "HealthCheck":
        return cls(
            status=HealthStatus.DEGRADED,
            version=version,
            services=services,
        )


class DatabaseHealthChecker:
    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    async def check(self) -> Dict[str, Any]:
        try:
            async with self._session_factory() as session:
                await session.execute(
                    __import__("sqlalchemy").text("SELECT 1")
                )
            return {"status": "healthy", "message": "Database connection OK"}
        except Exception as e:
            logger.error("Database health check failed: %s", e)
            return {"status": "unhealthy", "message": str(e)}


class RabbitMQHealthChecker:
    def __init__(self, rabbitmq_client: Any) -> None:
        self._client = rabbitmq_client

    async def check(self) -> Dict[str, Any]:
        try:
            if self._client._channel and self._client._channel.is_closed is False:
                return {"status": "healthy", "message": "RabbitMQ connection OK"}
            return {"status": "degraded", "message": "RabbitMQ not connected"}
        except Exception as e:
            logger.error("RabbitMQ health check failed: %s", e)
            return {"status": "unhealthy", "message": str(e)}


class RedisHealthChecker:
    def __init__(self, redis_client: Any) -> None:
        self._client = redis_client

    async def check(self) -> Dict[str, Any]:
        try:
            if self._client.client:
                await self._client.client.ping()
                return {"status": "healthy", "message": "Redis connection OK"}
            return {"status": "degraded", "message": "Redis not connected"}
        except Exception as e:
            logger.error("Redis health check failed: %s", e)
            return {"status": "unhealthy", "message": str(e)}


def create_health_router(
    service_name: str,
    db_checker: Optional[DatabaseHealthChecker] = None,
    mq_checker: Optional[RabbitMQHealthChecker] = None,
    redis_checker: Optional[RedisHealthChecker] = None,
) -> APIRouter:
    router = APIRouter()
    settings = get_settings()

    @router.get("/health", response_model=HealthCheck, tags=["health"])
    async def health_check():
        services: Dict[str, Any] = {
            service_name: {"status": "running"},
        }

        all_healthy = True

        if db_checker:
            db_status = await db_checker.check()
            services["database"] = db_status
            if db_status["status"] != "healthy":
                all_healthy = False

        if mq_checker:
            mq_status = await mq_checker.check()
            services["rabbitmq"] = mq_status
            if mq_status["status"] != "healthy":
                all_healthy = False

        if redis_checker:
            redis_status = await redis_checker.check()
            services["redis"] = redis_status
            if redis_status["status"] != "healthy":
                all_healthy = False

        status = HealthStatus.HEALTHY if all_healthy else HealthStatus.DEGRADED
        return HealthCheck(
            status=status,
            version=settings.APP_VERSION,
            services=services,
        )

    return router
