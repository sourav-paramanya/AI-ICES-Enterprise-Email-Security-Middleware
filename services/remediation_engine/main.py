"""AI-ICES Remediation Engine.

Performs post-delivery threat remediation via Zimbra SOAP API.
Supports mail search, quarantine, deletion, and restoration (clawback).
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

SERVICE_NAME = "remediation_engine"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service",
        settings.APP_NAME,
        "Remediation Engine",
    )
    from shared.rabbitmq import get_rabbitmq_client
    rabbitmq = get_rabbitmq_client()
    await rabbitmq.connect()
    DIContainer.register("rabbitmq", rabbitmq)

    from services.remediation_engine.tasks import process_remediation_message
    await rabbitmq.consume("remediation_queue", process_remediation_message)

    logger.info("Remediation Engine initialized and listening for messages")
    yield

    await rabbitmq.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "Remediation Engine",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - Remediation Engine",
    description="Post-delivery email remediation via Zimbra SOAP clawback",
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

from services.remediation_engine.routers import remediate
app.include_router(remediate.router)
