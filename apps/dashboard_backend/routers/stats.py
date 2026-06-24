"""Dashboard statistics endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from apps.dashboard_backend.dependencies import get_db
from shared.database.models.email_logs import EmailLog
from shared.database.models.threat_events import ThreatEvent
from shared.database.models.remediation_history import RemediationHistory
from shared.database.models.url_click_logs import UrlClickLog
from shared.schemas.governance import DashboardStats

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])

@router.get("/", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    # Aggregations
    total_emails = (await db.execute(select(func.count()).select_from(EmailLog))).scalar() or 0
    threats = (await db.execute(select(func.count()).select_from(ThreatEvent))).scalar() or 0
    remediations = (await db.execute(select(func.count()).select_from(RemediationHistory))).scalar() or 0
    url_clicks = (await db.execute(select(func.count()).select_from(UrlClickLog))).scalar() or 0
    
    # Placeholder for more complex analytics
    return DashboardStats(
        total_emails_processed=total_emails,
        threats_detected=threats,
        remediations_performed=remediations,
        url_clicks_blocked=url_clicks,
        average_scan_time_ms=0.0,
        clawback_success_rate=0.0,
        threats_by_type={},
        emails_over_time=[],
    )
