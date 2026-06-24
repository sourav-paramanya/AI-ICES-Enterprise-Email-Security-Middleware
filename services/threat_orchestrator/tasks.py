"""Threat Orchestrator RabbitMQ consumer tasks."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from aio_pika.abc import AbstractIncomingMessage

from shared.database.models.email_logs import EmailLog
from shared.database.models.threat_events import ThreatEvent
from shared.database.session import async_session_factory
from shared.rabbitmq import get_rabbitmq_client

logger = logging.getLogger(__name__)

# In-memory buffer for accumulating engine results per session
_pending_results: Dict[str, Dict[str, Any]] = {}


async def process_scoring_message(message: AbstractIncomingMessage) -> None:
    """Process incoming scoring messages from analysis engines."""
    async with message.process(ignore_processed=True):
        try:
            payload = json.loads(message.body)
            session_id = payload.get("session_id", "unknown")
            source = payload.get("source", "unknown")
            message_id = payload.get("message_id", "")
            result = payload.get("result", {})

            logger.debug("Scoring input from %s for session=%s", source, session_id)

            # Accumulate results in buffer
            if session_id not in _pending_results:
                _pending_results[session_id] = {
                    "message_id": message_id,
                    "results": {},
                }
            _pending_results[session_id]["results"][source] = result

            stored = _pending_results[session_id]["results"]

            # Check if all engines have reported (at least 2 for minimum verdict)
            if len(stored) >= 2 or len(stored) >= 4:
                await _process_final_verdict(session_id, stored, message_id)
                _pending_results.pop(session_id, None)

        except Exception as e:
            logger.error("Scoring processing error: %s", str(e), exc_info=True)


async def _process_final_verdict(
    session_id: str,
    results: Dict[str, Any],
    message_id: str,
) -> None:
    """Calculate final verdict and persist results."""
    from services.threat_orchestrator.scorer import get_threat_scorer

    scorer = get_threat_scorer()
    score_result = scorer.calculate_score(results)

    logger.info(
        "Final verdict for session=%s: score=%.4f verdict=%s type=%s",
        session_id,
        score_result["threat_score"],
        score_result["verdict"],
        score_result["threat_type"],
    )

    # Persist to database
    async with async_session_factory() as db:
        try:
            # Update email_log
            email_log = await db.get(EmailLog, session_id)
            if not email_log:
                # Try finding by session_id
                from sqlalchemy import select
                stmt = select(EmailLog).where(EmailLog.session_id == session_id)
                result = await db.execute(stmt)
                email_log = result.scalar_one_or_none()

            if email_log:
                email_log.threat_score = score_result["threat_score"]
                email_log.verdict = score_result["verdict"]
                email_log.threat_type = score_result["threat_type"]
                email_log.is_analyzed = True

            # Create threat event
            threat_event = ThreatEvent(
                email_log_id=email_log.id if email_log else None,
                threat_type=score_result["threat_type"],
                threat_score=score_result["threat_score"],
                verdict=score_result["verdict"],
                nlp_score=results.get("nlp", {}).get("score"),
                nlp_label=results.get("nlp", {}).get("label"),
                nlp_confidence=results.get("nlp", {}).get("confidence"),
                vision_score=results.get("vision", {}).get("image_phishing_score"),
                detected_urls=results.get("vision", {}).get("detected_urls"),
                ocr_text=results.get("vision", {}).get("ocr_text"),
                url_score=results.get("url", {}).get("max_score"),
                url_verdict="malicious" if results.get("url", {}).get("has_malicious") else "safe",
                cdr_status=results.get("cdr", {}).get("overall_status"),
                cdr_details=results.get("cdr", {}),
                detected_at=datetime.now(timezone.utc),
            )
            db.add(threat_event)
            await db.commit()

        except Exception as e:
            logger.error("Failed to persist verdict: %s", str(e))
            await db.rollback()

    # If blocking/high-risk, trigger remediation
    if score_result["verdict"] in ("BLOCK", "QUARANTINE"):
        await _trigger_remediation(session_id, message_id, score_result)


async def _trigger_remediation(
    session_id: str,
    message_id: str,
    score_result: Dict[str, Any],
) -> None:
    """Publish remediation action to remediation queue."""
    rabbitmq = get_rabbitmq_client()

    remediation_payload = {
        "session_id": session_id,
        "message_id": message_id,
        "action": score_result["verdict"].lower(),  # "quarantine" or "block"
        "threat_score": score_result["threat_score"],
        "threat_type": score_result["threat_type"],
        "verdict": score_result["verdict"],
    }

    await rabbitmq.publish(
        exchange_name="remediation.exchange",
        routing_key="remediation",
        payload=remediation_payload,
    )

    logger.info(
        "Triggered remediation for session=%s: action=%s",
        session_id,
        score_result["verdict"],
    )
