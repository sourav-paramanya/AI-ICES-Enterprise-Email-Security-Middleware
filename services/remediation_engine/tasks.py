"""Remediation Engine RabbitMQ consumer tasks."""

import json
import logging
from datetime import datetime, timezone

from aio_pika.abc import AbstractIncomingMessage

from shared.database.models.remediation_history import RemediationHistory
from shared.database.session import async_session_factory
from shared.rabbitmq import get_rabbitmq_client

logger = logging.getLogger(__name__)


async def process_remediation_message(message: AbstractIncomingMessage) -> None:
    """Process incoming remediation messages from RabbitMQ."""
    async with message.process(ignore_processed=True):
        try:
            payload = json.loads(message.body)
            session_id = payload.get("session_id", "unknown")
            action = payload.get("action", "quarantine")
            message_id = payload.get("message_id", "")
            threat_score = payload.get("threat_score", 0)
            threat_type = payload.get("threat_type", "")

            logger.info(
                "Processing remediation for session=%s action=%s",
                session_id,
                action,
            )

            from services.remediation_engine.clawback import get_zimbra_client
            client = get_zimbra_client()
            await client.initialize()

            # Authenticate
            try:
                await client.authenticate()
            except Exception as e:
                logger.error("Zimbra auth failed for remediation: %s", str(e))
                await _record_remediation(session_id, action, "failed", str(e))
                return

            # Find the email by message_id
            try:
                matches = await client.search_email(f"message-id:{message_id}")
            except Exception as e:
                logger.error("Email search failed: %s", str(e))
                await _record_remediation(session_id, action, "failed", str(e))
                return

            if not matches:
                logger.warning("No email found for message_id=%s", message_id)
                await _record_remediation(session_id, action, "not_found", "Email not found")
                return

            # Execute remediation action
            email_id = matches[0].get("id", "")
            recipient = matches[0].get("from", "")

            try:
                if action in ("quarantine", "block"):
                    result = await client.move_to_quarantine(email_id, recipient)
                    status = "quarantined"
                elif action == "delete":
                    result = await client.delete_email(email_id, recipient)
                    status = "deleted"
                elif action == "restore":
                    result = await client.restore_email(email_id, recipient)
                    status = "restored"
                else:
                    result = {"status": "unknown_action"}
                    status = "failed"

                await _record_remediation(session_id, action, status, None, result)
                logger.info(
                    "Remediation %s for session=%s: %s",
                    action,
                    session_id,
                    status,
                )

            except Exception as e:
                logger.error("Remediation action failed: %s", str(e))
                await _record_remediation(session_id, action, "failed", str(e))

            await client.close()

        except Exception as e:
            logger.error("Remediation processing error: %s", str(e), exc_info=True)


async def _record_remediation(
    session_id: str,
    action: str,
    status: str,
    error: Optional[str] = None,
    result: Optional[dict] = None,
) -> None:
    """Record remediation action in database."""
    async with async_session_factory() as db:
        try:
            from sqlalchemy import select
            from shared.database.models.email_logs import EmailLog

            stmt = select(EmailLog).where(EmailLog.session_id == session_id)
            email_log = (await db.execute(stmt)).scalar_one_or_none()

            history = RemediationHistory(
                email_log_id=email_log.id if email_log else None,
                action=action,
                status=status,
                initiated_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                zimbra_response=result,
                error_message=error,
                retry_count=0,
                max_retries=3,
            )
            db.add(history)
            await db.commit()

        except Exception as e:
            logger.error("Failed to record remediation history: %s", str(e))
            await db.rollback()
