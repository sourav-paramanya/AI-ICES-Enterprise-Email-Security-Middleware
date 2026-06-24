"""Vision Engine RabbitMQ consumer tasks."""

import base64
import json
import logging
from typing import Any, Dict

from aio_pika.abc import AbstractIncomingMessage

from services.vision_engine.processor import get_vision_processor
from shared.rabbitmq import get_rabbitmq_client

logger = logging.getLogger(__name__)


async def process_vision_message(message: AbstractIncomingMessage) -> None:
    """Process incoming vision analysis messages from RabbitMQ."""
    async with message.process(ignore_processed=True):
        try:
            payload = json.loads(message.body)
            session_id = payload.get("session_id", "unknown")
            attachments = payload.get("attachments", [])
            message_id = payload.get("message_id", "")

            logger.info(
                "Processing Vision for session=%s attachments=%d",
                session_id,
                len(attachments),
            )

            processor = get_vision_processor()
            vision_results = []

            for attachment in attachments:
                content_type = attachment.get("content_type", "")
                if not content_type.startswith("image/"):
                    continue

                image_data = attachment.get("data")
                if not image_data:
                    continue

                try:
                    image_bytes = base64.b64decode(image_data)
                    result = processor.process_image(image_bytes)
                    vision_results.append({
                        "filename": attachment.get("filename", "unknown"),
                        "result": result,
                    })
                except Exception as e:
                    logger.error(
                        "Vision processing error for attachment %s: %s",
                        attachment.get("filename", "unknown"),
                        str(e),
                    )

            # Aggregate results
            aggregated = _aggregate_vision_results(vision_results)

            # Publish to threat scoring queue
            scoring_payload = {
                "session_id": session_id,
                "message_id": message_id,
                "source": "vision",
                "result": aggregated,
                "individual_results": vision_results,
            }

            rabbitmq = get_rabbitmq_client()
            await rabbitmq.publish(
                exchange_name="security.analysis.exchange",
                routing_key="scoring",
                payload=scoring_payload,
            )

            logger.info(
                "Vision result for session=%s: urls=%d qr=%d score=%.4f",
                session_id,
                len(aggregated.get("detected_urls", [])),
                len(aggregated.get("qr_codes", [])),
                aggregated.get("image_phishing_score", 0),
            )

        except Exception as e:
            logger.error("Vision processing error: %s", str(e), exc_info=True)


def _aggregate_vision_results(results: list) -> Dict[str, Any]:
    """Aggregate multiple vision processing results."""
    all_urls: list = []
    all_qr: list = []
    max_phishing_score = 0.0

    for item in results:
        result = item.get("result", {})
        all_urls.extend(result.get("detected_urls", []))
        all_qr.extend(result.get("qr_codes", []))
        max_phishing_score = max(
            max_phishing_score,
            result.get("image_phishing_score", 0),
        )

    return {
        "detected_urls": list(set(all_urls)),
        "qr_codes": all_qr,
        "has_qr": any(qr.get("data") for qr in all_qr),
        "has_text": any(item.get("result", {}).get("has_text") for item in results),
        "image_phishing_score": max_phishing_score,
        "images_processed": len(results),
    }
