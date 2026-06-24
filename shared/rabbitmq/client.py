import json
import logging
from functools import lru_cache
from typing import Any, Callable, Dict, Optional

from aio_pika import ExchangeType, Message, connect_robust
from aio_pika.abc import AbstractChannel, AbstractConnection, AbstractExchange

from shared.config.settings import get_settings

logger = logging.getLogger(__name__)


class RabbitMQClient:
    def __init__(self) -> None:
        self._connection: Optional[AbstractConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self._exchanges: Dict[str, AbstractExchange] = {}

    async def connect(self) -> None:
        settings = get_settings()
        self._connection = await connect_robust(
            settings.RABBITMQ_URL,
            timeout=10,
        )
        self._channel = await self._connection.channel()
        await self._channel.set_qos(prefetch_count=10)
        logger.info("Connected to RabbitMQ at %s:%s", settings.RABBITMQ_HOST, settings.RABBITMQ_PORT)

    async def close(self) -> None:
        if self._channel and not self._channel.is_closed:
            await self._channel.close()
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
        logger.info("Disconnected from RabbitMQ")

    async def declare_exchange(
        self,
        name: str,
        exchange_type: ExchangeType = ExchangeType.DIRECT,
        durable: bool = True,
    ) -> AbstractExchange:
        exchange = await self._channel.declare_exchange(
            name,
            exchange_type,
            durable=durable,
        )
        self._exchanges[name] = exchange
        logger.debug("Declared exchange: %s (%s)", name, exchange_type.value)
        return exchange

    async def declare_queue(
        self,
        name: str,
        durable: bool = True,
        dead_letter_exchange: Optional[str] = None,
        dead_letter_routing_key: Optional[str] = None,
        **kwargs: Any,
    ) -> Any:
        arguments = {}
        if dead_letter_exchange:
            arguments["x-dead-letter-exchange"] = dead_letter_exchange
        if dead_letter_routing_key:
            arguments["x-dead-letter-routing-key"] = dead_letter_routing_key

        queue = await self._channel.declare_queue(
            name,
            durable=durable,
            arguments=arguments or None,
        )
        logger.debug("Declared queue: %s", name)
        return queue

    async def bind_queue(
        self,
        queue_name: str,
        exchange_name: str,
        routing_key: str,
    ) -> None:
        queue = await self._channel.declare_queue(queue_name, durable=True)
        exchange = self._exchanges.get(exchange_name)
        if not exchange:
            exchange = await self.declare_exchange(exchange_name)
        await queue.bind(exchange, routing_key=routing_key)
        logger.debug(
            "Bound queue %s to exchange %s with key %s",
            queue_name,
            exchange_name,
            routing_key,
        )

    async def publish(
        self,
        exchange_name: str,
        routing_key: str,
        payload: Dict[str, Any],
        delivery_mode: int = 2,
        content_type: str = "application/json",
    ) -> None:
        exchange = self._exchanges.get(exchange_name)
        if not exchange:
            exchange = await self.declare_exchange(exchange_name)

        message = Message(
            body=json.dumps(payload, default=str).encode(),
            delivery_mode=delivery_mode,
            content_type=content_type,
        )
        await exchange.publish(message, routing_key=routing_key)
        logger.debug(
            "Published message to %s with key %s",
            exchange_name,
            routing_key,
        )

    async def consume(
        self,
        queue_name: str,
        callback: Callable,
        prefetch_count: int = 10,
    ) -> None:
        queue = await self._channel.declare_queue(queue_name, durable=True)
        await self._channel.set_qos(prefetch_count=prefetch_count)
        await queue.consume(callback)
        logger.info(
            "Started consuming from queue: %s",
            queue_name,
        )

    @property
    def is_connected(self) -> bool:
        return (
            self._connection is not None
            and not self._connection.is_closed
            and self._channel is not None
            and not self._channel.is_closed
        )


@lru_cache
def get_rabbitmq_client() -> RabbitMQClient:
    return RabbitMQClient()
