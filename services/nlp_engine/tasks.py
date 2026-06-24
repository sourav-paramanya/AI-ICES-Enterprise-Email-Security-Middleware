"""NLP Engine RabbitMQ consumer tasks."""

import json
import logging
from typing import Any, Dict

from aio_pika.abc import AbstractIncomingMessage

from services.nlp_engine.classifier import get_nlp_classifier
from shared.rabbitmq import get_rabbitmq_client

logger = logging.getLogger(__name__)


async def process_nlp_message(message: AbstractIncomingMessage) -> None:
    """Process incoming NLP analysis messages from RabbitMQ."""
    async with message.process(ignore_processed=True):
        try:
            payload = json.loads(message.body)
            session_id = payload.get("session_id", "unknown")
            body_text = payload.get("body_text", "")
            message_id = payload.get("message_id", "")

            logger.info("Processing NLP for session=%s message=%s", session_id, message_id)

            classifier = get_nlp_classifier()
            result = classifier.predict(body_text)

            # Publish result to threat scoring queue
            scoring_payload = {
                "session_id": session_id,
                "message_id": message_id,
                "source": "nlp",
                "result": result,
            }

            rabbitmq = get_rabbitmq_client()
            await rabbitmq.publish(
                exchange_name="security.analysis.exchange",
                routing_key="scoring",
                payload=scoring_payload,
            )

            logger.info(
                "NLP result for session=%s: label=%s score=%.4f",
                session_id,
                result["label"],
                result.get("score", 0),
            )

        except Exception as e:
            logger.error("NLP processing error: %s", str(e), exc_info=True)
