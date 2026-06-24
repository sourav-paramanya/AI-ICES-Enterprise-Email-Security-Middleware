import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.core_hub.dependencies import get_db, get_rabbitmq, get_redis
from shared.rabbitmq import RabbitMQClient
from shared.redis import RedisClient
from shared.schemas.email import EmailPayload, IngestError, IngestResponse

router = APIRouter(prefix="/api/v1", tags=["ingest"])


@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=202,
    summary="Ingest email payload for analysis",
    description="Receives email payload from Gateway, validates, and queues for async AI analysis",
    responses={
        202: {"description": "Payload queued successfully"},
        400: {"model": IngestError, "description": "Invalid payload"},
        503: {"model": IngestError, "description": "Queue unavailable"},
    },
)
async def ingest_email(
    payload: EmailPayload,
    db: AsyncSession = Depends(get_db),
    rabbitmq: RabbitMQClient = Depends(get_rabbitmq),
    redis: RedisClient = Depends(get_redis),
):
    message_id = payload.message_id or str(uuid.uuid4())

    # Validate session_id uniqueness via Redis (idempotency)
    existing = await redis.get(f"session:{payload.session_id}")
    if existing:
        raise HTTPException(
            status_code=409,
            detail={
                "status": "DUPLICATE",
                "session_id": payload.session_id,
                "message_id": message_id,
                "detail": "Session ID already processed",
                "error_code": "SESSION_DUPLICATE",
            },
        )

    try:
        # Store session in Redis with TTL for dedup
        await redis.set(
            f"session:{payload.session_id}",
            message_id,
            ttl=86400,
        )

        # Publish to RabbitMQ for async processing
        routing_key = "nlp"
        await rabbitmq.publish(
            exchange_name="email.ingest.exchange",
            routing_key=routing_key,
            payload={
                "session_id": payload.session_id,
                "message_id": message_id,
                "sender": payload.sender,
                "recipients": payload.recipients,
                "subject": payload.subject,
                "body_text": payload.body_text,
                "body_html": payload.body_html,
                "headers": payload.headers,
                "attachments": [a.model_dump() for a in payload.attachments],
                "received_at": (
                    payload.received_at.isoformat()
                    if payload.received_at
                    else datetime.now(timezone.utc).isoformat()
                ),
                "email_size": payload.email_size,
            },
        )

        # Also persist to database
        from shared.database.models.email_logs import EmailLog

        email_log = EmailLog(
            session_id=payload.session_id,
            message_id=message_id,
            sender=payload.sender,
            recipients=payload.recipients,
            subject=payload.subject,
            body_text=payload.body_text,
            body_html=payload.body_html,
            headers=payload.headers,
            attachments_metadata=[a.model_dump() for a in payload.attachments],
            attachment_count=len(payload.attachments),
            email_size=payload.email_size,
            has_attachments=len(payload.attachments) > 0,
            received_at=payload.received_at or datetime.now(timezone.utc),
        )
        db.add(email_log)
        await db.flush()

        return IngestResponse(
            session_id=payload.session_id,
            message_id=message_id,
        )

    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "ERROR",
                "session_id": payload.session_id,
                "message_id": message_id,
                "detail": f"Failed to queue email: {str(e)}",
                "error_code": "QUEUE_FAILURE",
            },
        )
