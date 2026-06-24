"""AI-ICES Threat Orchestrator.

Aggregates results from NLP, Vision, URL, and CDR engines.
Computes a weighted threat score and produces a final verdict:
ALLOW, SUSPICIOUS, QUARANTINE, or BLOCK.
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

SERVICE_NAME = "threat_orchestrator"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service",
        settings.APP_NAME,
        "Threat Orchestrator",
    )
    from services.threat_orchestrator.scorer import get_threat_scorer
    scorer = get_threat_scorer()
    DIContainer.register("threat_scorer", scorer)

    from shared.rabbitmq import get_rabbitmq_client
    rabbitmq = get_rabbitmq_client()
    await rabbitmq.connect()
    DIContainer.register("rabbitmq", rabbitmq)

    from services.threat_orchestrator.tasks import process_scoring_message
    await rabbitmq.consume("threat_score_queue", process_scoring_message)

    logger.info("Threat Orchestrator initialized and listening for scoring messages")
    yield

    await rabbitmq.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "Threat Orchestrator",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - Threat Orchestrator",
    description="Aggregates detection results and produces final threat verdict",
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

from services.threat_orchestrator.routers import scoring
app.include_router(scoring.router)
