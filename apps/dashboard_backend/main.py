"""AI-ICES Dashboard Backend.

Backend API for the React-based SOC dashboard.
Provides endpoints consumed by the dashboard frontend for threat monitoring,
email exploration, URL analytics, remediation center, and audit trails.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared.config.settings import get_settings
from shared.logging.logger import setup_logging
from shared.utils.health import create_health_router

settings = get_settings()
setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
logger = logging.getLogger(__name__)

SERVICE_NAME = "dashboard_backend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service on port %s",
        settings.APP_NAME,
        "Dashboard Backend",
        settings.DASHBOARD_BACKEND_PORT,
    )
    # TODO: Initialize database connection
    # TODO: Initialize Redis for session management
    yield
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "Dashboard Backend",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - Dashboard Backend",
    description="Backend API for the SOC dashboard frontend",
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

from apps.dashboard_backend.routers import health, stats, threats, remediation

app.include_router(health.router, tags=["health"])
app.include_router(stats.router)
app.include_router(threats.router)
app.include_router(remediation.router)
