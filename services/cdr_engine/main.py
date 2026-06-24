"""AI-ICES Content Disarm & Reconstruction (CDR) Engine.

Sanitizes PDF, DOCX, XLSX, and PPTX attachments by removing
macros, JavaScript, embedded objects, and auto-actions,
then reconstructs a safe version of the file.
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

SERVICE_NAME = "cdr_engine"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service",
        settings.APP_NAME,
        "CDR Engine",
    )
    # Initialize RabbitMQ consumer
    from shared.rabbitmq import get_rabbitmq_client
    rabbitmq = get_rabbitmq_client()
    await rabbitmq.connect()
    DIContainer.register("rabbitmq", rabbitmq)

    # Start consuming from CDR analysis queue
    from services.cdr_engine.tasks import process_cdr_message
    await rabbitmq.consume("cdr_analysis_queue", process_cdr_message)

    logger.info("CDR Engine initialized and listening for messages")
    yield

    await rabbitmq.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "CDR Engine",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - CDR Engine",
    description="Content Disarm & Reconstruction for PDF, DOCX, XLSX, PPTX",
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

from services.cdr_engine.routers import sanitize
app.include_router(sanitize.router)
