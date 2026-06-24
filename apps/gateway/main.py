"""AI-ICES Gateway Service.

Receives SMTP traffic from Zimbra Postfix Milter, parses email content,
and forwards payloads to the Core Hub for asynchronous processing.
"""

import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config.settings import get_settings
from shared.logging.logger import setup_logging
from shared.utils.health import create_health_router

settings = get_settings()
setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)
logger = logging.getLogger(__name__)

SERVICE_NAME = "gateway"

_milter_thread: threading.Thread = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _milter_thread
    logger.info(
        "Starting %s - %s Service on port %s",
        settings.APP_NAME,
        SERVICE_NAME.capitalize(),
        settings.GATEWAY_PORT,
    )

    # Start Milter listener in a background thread
    from apps.gateway.milter_handler import start_milter_server

    _milter_thread = threading.Thread(target=start_milter_server, daemon=True)
    _milter_thread.start()
    logger.info("Milter listener started on port %s", settings.GATEWAY_PORT)

    yield

    logger.info(
        "Shutting down %s - %s Service",
        settings.APP_NAME,
        SERVICE_NAME.capitalize(),
    )


app = FastAPI(
    title=f"{settings.APP_NAME} - Gateway Service",
    description="Email interception gateway via Postfix Milter protocol",
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
