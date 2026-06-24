"""URL Protection RabbitMQ consumer tasks."""

import json
import logging
from typing import Any, Dict

from aio_pika.abc import AbstractIncomingMessage

from services.url_protection.service import get_url_protection_service
from shared.rabbitmq import get_rabbitmq_client

logger = logging.getLogger(__name__)


async def process_url_message(message: AbstractIncomingMessage) -> None:
    """Process incoming URL analysis messages from RabbitMQ."""
    async with message.process(ignore_processed=True):
        try:
            payload = json.loads(message.body)
            session_id = payload.get("session_id", "unknown")
            body_text = payload.get("body_text", "")
            body_html = payload.get("body_html", "")
            message_id = payload.get("message_id", "")

            logger.info("Processing URL analysis for session=%s", session_id)

            service = get_url_protection_service()

            # Extract URLs from text and HTML
            urls = service.extract_urls(body_text)
            html_urls = service.extract_urls(body_html or "")
            all_urls = list(set(urls + html_urls))

            if not all_urls:
                # No URLs found, publish empty result
                await _publish_result(session_id, message_id, {
                    "url_count": 0,
                    "urls": [],
                    "average_score": 0.0,
                    "max_score": 0.0,
                    "has_malicious": False,
                })
                return

            # Check reputation for each URL
            url_results = []
            for url in all_urls:
                token, rewritten = service.encrypt_url(url)
                reputation = await service.check_reputation(url)
                url_results.append({
                    "original_url": url,
                    "rewritten_url": rewritten,
                    "token": token,
                    "reputation": reputation,
                })

            scores = [r["reputation"]["score"] for r in url_results]
            aggregated = {
                "url_count": len(all_urls),
                "urls": url_results,
                "average_score": sum(scores) / len(scores) if scores else 0.0,
                "max_score": max(scores) if scores else 0.0,
                "has_malicious": any(r["reputation"]["is_malicious"] for r in url_results),
            }

            await _publish_result(session_id, message_id, aggregated)

            logger.info(
                "URL result for session=%s: %d URLs, %d malicious",
                session_id,
                len(all_urls),
                sum(1 for r in url_results if r["reputation"]["is_malicious"]),
            )

        except Exception as e:
            logger.error("URL processing error: %s", str(e), exc_info=True)


async def _publish_result(session_id: str, message_id: str, aggregated: Dict[str, Any]) -> None:
    """Publish URL analysis result to threat scoring queue."""
    scoring_payload = {
        "session_id": session_id,
        "message_id": message_id,
        "source": "url",
        "result": aggregated,
    }

    rabbitmq = get_rabbitmq_client()
    await rabbitmq.publish(
        exchange_name="security.analysis.exchange",
        routing_key="scoring",
        payload=scoring_payload,
    )
