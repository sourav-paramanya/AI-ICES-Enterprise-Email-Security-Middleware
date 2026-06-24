"""Vision Engine dependency injection."""

import logging
from typing import AsyncGenerator

from shared.rabbitmq import RabbitMQClient, get_rabbitmq_client

logger = logging.getLogger(__name__)


async def get_rabbitmq() -> AsyncGenerator[RabbitMQClient, None]:
    client = get_rabbitmq_client()
    if not client.is_connected:
        await client.connect()
    try:
        yield client
    finally:
        pass
