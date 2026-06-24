"""AI-ICES Vision Engine.

Performs image-based threat detection using PaddleOCR, OpenCV, and PyZbar.
Detects quishing, image phishing, hidden text, and QR redirection attacks.
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

SERVICE_NAME = "vision_engine"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service",
        settings.APP_NAME,
        "Vision Engine",
    )
    # Initialize Vision processor
    from services.vision_engine.processor import get_vision_processor
    processor = get_vision_processor()
    DIContainer.register("vision_processor", processor)

    # Initialize RabbitMQ consumer
    from shared.rabbitmq import get_rabbitmq_client
    rabbitmq = get_rabbitmq_client()
    await rabbitmq.connect()
    DIContainer.register("rabbitmq", rabbitmq)

    # Start consuming from vision analysis queue
    from services.vision_engine.tasks import process_vision_message
    await rabbitmq.consume("vision_analysis_queue", process_vision_message)

    logger.info("Vision Engine initialized and listening for messages")
    yield

    await rabbitmq.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "Vision Engine",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - Vision Engine",
    description="Computer vision threat detection using PaddleOCR and OpenCV",
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

from services.vision_engine.routers import scan
app.include_router(scan.router)
