"""CDR Engine RabbitMQ consumer tasks."""

import base64
import json
import logging

from aio_pika.abc import AbstractIncomingMessage

from services.cdr_engine.sanitizer import get_cdr_sanitizer
from shared.rabbitmq import get_rabbitmq_client

logger = logging.getLogger(__name__)


async def process_cdr_message(message: AbstractIncomingMessage) -> None:
    """Process incoming CDR analysis messages from RabbitMQ."""
    async with message.process(ignore_processed=True):
        try:
            payload = json.loads(message.body)
            session_id = payload.get("session_id", "unknown")
            attachments = payload.get("attachments", [])
            message_id = payload.get("message_id", "")

            logger.info("Processing CDR for session=%s attachments=%d", session_id, len(attachments))

            sanitizer = get_cdr_sanitizer()
            cdr_results = []

            for attachment in attachments:
                content_type = attachment.get("content_type", "")
                filename = attachment.get("filename", "unknown")

                if not sanitizer.is_supported(content_type, filename):
                    continue

                file_data = attachment.get("data")
                if not file_data:
                    continue

                try:
                    file_bytes = base64.b64decode(file_data)
                    result = sanitizer.sanitize(file_bytes, content_type, filename)
                    cdr_results.append({
                        "filename": filename,
                        "result": result,
                    })
                except Exception as e:
                    logger.error(
                        "CDR error for %s: %s",
                        filename,
                        str(e),
                    )

            # Aggregate
            all_issues = []
            all_statuses = set()
            for item in cdr_results:
                all_issues.extend(item["result"].get("issues_removed", []))
                all_statuses.add(item["result"]["status"])

            aggregated = {
                "files_processed": len(cdr_results),
                "issues_found": all_issues,
                "overall_status": "sanitized" if "error" not in all_statuses else "partial",
                "results": cdr_results,
            }

            # Publish to scoring queue
            scoring_payload = {
                "session_id": session_id,
                "message_id": message_id,
                "source": "cdr",
                "result": aggregated,
            }

            rabbitmq = get_rabbitmq_client()
            await rabbitmq.publish(
                exchange_name="security.analysis.exchange",
                routing_key="scoring",
                payload=scoring_payload,
            )

            logger.info(
                "CDR result for session=%s: %d files, %d issues",
                session_id,
                len(cdr_results),
                len(all_issues),
            )

        except Exception as e:
            logger.error("CDR processing error: %s", str(e), exc_info=True)
