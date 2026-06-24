"""AI-ICES URL Protection Service.

Provides URL rewriting, time-of-click gateway, and live threat intelligence validation.
Protects users from delayed weaponized URLs via encrypted redirects and reputation checks.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config.settings import get_settings
from shared.logging.logger import setup_logging
from shared.utils.di import DIContainer
from shared.utils.health import create_health_router

settings = get_settings()
setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
logger = logging.getLogger(__name__)

SERVICE_NAME = "url_protection"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service",
        settings.APP_NAME,
        "URL Protection",
    )
    # Initialize URL protection service
    from services.url_protection.service import get_url_protection_service
    service = get_url_protection_service()
    await service.initialize()
    DIContainer.register("url_protection_service", service)

    # Initialize RabbitMQ consumer
    from shared.rabbitmq import get_rabbitmq_client
    rabbitmq = get_rabbitmq_client()
    await rabbitmq.connect()
    DIContainer.register("rabbitmq", rabbitmq)

    # Start consuming from URL analysis queue
    from services.url_protection.tasks import process_url_message
    await rabbitmq.consume("url_analysis_queue", process_url_message)

    logger.info("URL Protection initialized and listening for messages")
    yield

    await service.close()
    await rabbitmq.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "URL Protection",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - URL Protection Service",
    description="URL rewriting, encryption, and time-of-click threat validation",
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

health_router = create_health_router(SERVICE_NAME)
app.include_router(health_router, tags=["health"])

from services.url_protection.routers import scan, redirect
app.include_router(scan.router)
app.include_router(redirect.router)
