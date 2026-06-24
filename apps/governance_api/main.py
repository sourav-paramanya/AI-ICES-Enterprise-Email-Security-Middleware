"""AI-ICES Governance API.

Centralized management and control plane for SOC operations.
Provides RBAC-protected endpoints for threat monitoring, email search,
remediation actions, URL analytics, audit trails, and false positive management.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config.settings import get_settings
from shared.logging.logger import setup_logging
from shared.utils.di import DIContainer
from shared.utils.health import (
    create_health_router,
    DatabaseHealthChecker,
    RedisHealthChecker,
)
from shared.database.session import async_session_factory
from shared.redis import get_redis_client

settings = get_settings()
setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
logger = logging.getLogger(__name__)

SERVICE_NAME = "governance_api"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service on port %s",
        settings.APP_NAME,
        "Governance API",
        settings.GOVERNANCE_API_PORT,
    )
    # Initialize Redis
    redis = get_redis_client()
    await redis.connect()
    DIContainer.register("redis", redis)

    yield

    await redis.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "Governance API",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - Governance API",
    description="Centralized SOC management, RBAC, and audit API",
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db_health = DatabaseHealthChecker(async_session_factory)
redis_health = RedisHealthChecker(get_redis_client())
health_router = create_health_router(SERVICE_NAME, db_health, redis_health=redis_health)
app.include_router(health_router, tags=["health"])

from apps.governance_api.routers import auth, users, threats, audit, roles
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(threats.router)
app.include_router(audit.router)
app.include_router(roles.router)
