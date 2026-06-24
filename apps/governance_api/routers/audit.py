"""Audit log endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from apps.governance_api.dependencies import get_db
from shared.database.models.audit_trails import AuditTrail

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditTrail)

    if action:
        query = query.where(AuditTrail.action == action)
    if actor_id:
        query = query.where(AuditTrail.actor_id == actor_id)
    if resource_type:
        query = query.where(AuditTrail.resource_type == resource_type)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size).order_by(AuditTrail.created_at.desc())
    logs = (await db.execute(query)).scalars().all()

    return {
        "items": [
            {
                "id": str(log.id),
                "actor_id": log.actor_id,
                "actor_email": log.actor_email,
                "actor_role": log.actor_role,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": log.details,
                "ip_address": log.ip_address,
                "status": log.status,
                "error_message": log.error_message,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/export")
async def export_audit_logs(
    format: str = Query("json"),
    db: AsyncSession = Depends(get_db),
):
    """Export audit logs for compliance."""
    logs = (await db.execute(
        select(AuditTrail).order_by(AuditTrail.created_at.desc()).limit(10000),
    )).scalars().all()

    items = [
        {
            "id": str(log.id),
            "timestamp": log.created_at.isoformat(),
            "actor": log.actor_email,
            "action": log.action,
            "resource": log.resource_type,
            "status": log.status,
            "details": log.details,
        }
        for log in logs
    ]

    return {"format": format, "count": len(items), "items": items}
