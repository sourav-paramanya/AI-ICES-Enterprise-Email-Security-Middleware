"""AI-ICES NLP Engine.

Performs text-based threat detection using DeBERTa-v3 transformer model.
Detects BEC, phishing, social engineering, credential harvesting, and financial fraud.
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

SERVICE_NAME = "nlp_engine"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service",
        settings.APP_NAME,
        "NLP Engine",
    )
    # Load the NLP classifier model
    from services.nlp_engine.classifier import get_nlp_classifier
    classifier = get_nlp_classifier()
    DIContainer.register("nlp_classifier", classifier)

    # Initialize RabbitMQ consumer for NLP analysis queue
    from shared.rabbitmq import get_rabbitmq_client
    rabbitmq = get_rabbitmq_client()
    await rabbitmq.connect()
    DIContainer.register("rabbitmq", rabbitmq)

    # Start consuming from NLP analysis queue
    from services.nlp_engine.tasks import process_nlp_message
    await rabbitmq.consume("nlp_analysis_queue", process_nlp_message)

    logger.info("NLP Engine initialized and listening for messages")
    yield

    await rabbitmq.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "NLP Engine",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - NLP Engine",
    description="NLP-based threat detection using DeBERTa-v3",
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

from services.nlp_engine.routers import predict
app.include_router(predict.router)
