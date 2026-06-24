"""Remediation dashboard endpoints."""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from apps.dashboard_backend.dependencies import get_db
from shared.database.models.remediation_history import RemediationHistory
from shared.schemas.governance import RemediationListResponse, RemediationResponse

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])

@router.get("/", response_model=RemediationListResponse)
async def list_remediations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(RemediationHistory)

    if status:
        query = query.where(RemediationHistory.status == status)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0
    query = query.offset((page - 1) * page_size).limit(page_size).order_by(RemediationHistory.initiated_at.desc())
    remediations = (await db.execute(query)).scalars().all()

    return RemediationListResponse(
        items=[RemediationResponse.model_validate(r) for r in remediations],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
    )
