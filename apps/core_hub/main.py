"""AI-ICES Core Hub API.

Central ingress point for email payloads. Validates incoming data,
publishes messages to RabbitMQ queues, and provides health/metrics endpoints.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config.settings import get_settings
from shared.logging.logger import setup_logging
from shared.rabbitmq import get_rabbitmq_client
from shared.redis import get_redis_client
from shared.utils.di import DIContainer
from shared.utils.health import create_health_router, DatabaseHealthChecker, RabbitMQHealthChecker, RedisHealthChecker

settings = get_settings()
setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
logger = logging.getLogger(__name__)

SERVICE_NAME = "core_hub"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s - %s Service on port %s",
        settings.APP_NAME,
        "Core Hub",
        settings.CORE_HUB_PORT,
    )
    # Initialize connections
    rabbitmq = get_rabbitmq_client()
    await rabbitmq.connect()

    redis = get_redis_client()
    await redis.connect()

    # Declare exchanges and queues
    await rabbitmq.declare_exchange("email.ingest.exchange")
    await rabbitmq.declare_exchange("security.analysis.exchange")
    await rabbitmq.declare_queue("nlp_analysis_queue", dead_letter_exchange="dlx", dead_letter_routing_key="dlq_email")
    await rabbitmq.declare_queue("vision_analysis_queue", dead_letter_exchange="dlx", dead_letter_routing_key="dlq_email")
    await rabbitmq.declare_queue("url_analysis_queue", dead_letter_exchange="dlx", dead_letter_routing_key="dlq_email")
    await rabbitmq.declare_queue("cdr_analysis_queue", dead_letter_exchange="dlx", dead_letter_routing_key="dlq_email")
    await rabbitmq.declare_queue("threat_score_queue", dead_letter_exchange="dlx", dead_letter_routing_key="dlq_ai")
    await rabbitmq.declare_queue("remediation_queue", dead_letter_exchange="dlx", dead_letter_routing_key="dlq_remediation")
    await rabbitmq.declare_exchange("dlx")
    await rabbitmq.declare_queue("dlq_email")
    await rabbitmq.declare_queue("dlq_ai")
    await rabbitmq.declare_queue("dlq_remediation")

    # Bind analysis queues to security.analysis exchange
    await rabbitmq.bind_queue("nlp_analysis_queue", "security.analysis.exchange", "nlp")
    await rabbitmq.bind_queue("vision_analysis_queue", "security.analysis.exchange", "vision")
    await rabbitmq.bind_queue("url_analysis_queue", "security.analysis.exchange", "url")
    await rabbitmq.bind_queue("cdr_analysis_queue", "security.analysis.exchange", "cdr")
    await rabbitmq.bind_queue("threat_score_queue", "security.analysis.exchange", "scoring")
    await rabbitmq.bind_queue("remediation_queue", "remediation.exchange", "remediation")

    # Bind email.ingest to nlp by default for initial analysis
    await rabbitmq.bind_queue("nlp_analysis_queue", "email.ingest.exchange", "nlp")

    DIContainer.register("rabbitmq", rabbitmq)
    DIContainer.register("redis", redis)

    yield

    await rabbitmq.close()
    await redis.close()
    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        "Core Hub",
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - Core Hub",
    description="Central email ingestion and queue management API",
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

# Health check with DB, RabbitMQ, Redis probes
from shared.database.session import async_session_factory
db_health = DatabaseHealthChecker(async_session_factory)
mq_health = RabbitMQHealthChecker(get_rabbitmq_client())
redis_health = RedisHealthChecker(get_redis_client())
health_router = create_health_router(SERVICE_NAME, db_health, mq_health, redis_health)
app.include_router(health_router, tags=["health"])

# Routers
from apps.core_hub.routers import ingest
app.include_router(ingest.router)
