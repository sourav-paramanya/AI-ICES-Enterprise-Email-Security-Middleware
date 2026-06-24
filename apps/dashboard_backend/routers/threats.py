"""Threat dashboard endpoints."""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from apps.dashboard_backend.dependencies import get_db
from shared.database.models.threat_events import ThreatEvent
from shared.schemas.governance import ThreatListResponse, ThreatResponse

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])

@router.get("/", response_model=ThreatListResponse)
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    threat_type: Optional[str] = None,
    verdict: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(ThreatEvent)

    if threat_type:
        query = query.where(ThreatEvent.threat_type == threat_type)
    if verdict:
        query = query.where(ThreatEvent.verdict == verdict)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0
    query = query.offset((page - 1) * page_size).limit(page_size).order_by(ThreatEvent.detected_at.desc())
    threats = (await db.execute(query)).scalars().all()

    return ThreatListResponse(
        items=[ThreatResponse.model_validate(t) for t in threats],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
    )
