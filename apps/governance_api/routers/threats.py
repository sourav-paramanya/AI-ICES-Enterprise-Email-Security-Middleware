"""Threat monitoring endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from apps.governance_api.dependencies import get_db
from shared.database.models.threat_events import ThreatEvent

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])


@router.get("/")
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    threat_type: Optional[str] = None,
    verdict: Optional[str] = None,
    min_score: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(ThreatEvent)

    if threat_type:
        query = query.where(ThreatEvent.threat_type == threat_type)
    if verdict:
        query = query.where(ThreatEvent.verdict == verdict)
    if min_score is not None:
        query = query.where(ThreatEvent.threat_score >= min_score)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size).order_by(ThreatEvent.detected_at.desc())
    threats = (await db.execute(query)).scalars().all()

    return {
        "items": [
            {
                "id": str(t.id),
                "threat_type": t.threat_type,
                "threat_score": t.threat_score,
                "verdict": t.verdict,
                "nlp_label": t.nlp_label,
                "nlp_score": t.nlp_score,
                "vision_label": t.vision_label,
                "vision_score": t.vision_score,
                "url_score": t.url_score,
                "cdr_status": t.cdr_status,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None,
            }
            for t in threats
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/stats")
async def threat_stats(db: AsyncSession = Depends(get_db)):
    """Get aggregated threat statistics."""
    # Total threats by type
    type_query = select(ThreatEvent.threat_type, func.count()).group_by(ThreatEvent.threat_type)
    type_results = (await db.execute(type_query)).all()

    # Total threats by verdict
    verdict_query = select(ThreatEvent.verdict, func.count()).group_by(ThreatEvent.verdict)
    verdict_results = (await db.execute(verdict_query)).all()

    return {
        "total_threats": sum(count for _, count in type_results),
        "by_type": {t: c for t, c in type_results},
        "by_verdict": {v: c for v, c in verdict_results},
    }
