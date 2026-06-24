"""Gateway service dependency injection."""

import logging
from typing import AsyncGenerator

from fastapi import Depends

from shared.rabbitmq import RabbitMQClient, get_rabbitmq_client
from shared.utils.di import DIContainer

logger = logging.getLogger(__name__)


async def get_rabbitmq() -> AsyncGenerator[RabbitMQClient, None]:
    client = get_rabbitmq_client()
    if not client.is_connected:
        await client.connect()
    try:
        yield client
    finally:
        pass
