"""Audit logging utility."""

from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from shared.database.models.audit_trails import AuditTrail
from shared.security.rbac import UserContext

async def record_audit(
    db: AsyncSession,
    user: UserContext,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    status: str = "success",
    error_message: Optional[str] = None,
):
    audit = AuditTrail(
        actor_id=user.user_id,
        actor_email=user.email,
        actor_role=user.role.value,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        status=status,
        error_message=error_message,
    )
    db.add(audit)
    await db.flush()
