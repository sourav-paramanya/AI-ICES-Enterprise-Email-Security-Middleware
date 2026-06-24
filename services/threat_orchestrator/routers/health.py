from fastapi import APIRouter
from shared.config.settings import get_settings
from shared.utils.health import HealthCheck, HealthStatus

router = APIRouter()
settings = get_settings()


@router.get("/health", response_model=HealthCheck, tags=["health"])
async def health_check():
    return HealthCheck(
        status=HealthStatus.HEALTHY,
        version=settings.APP_VERSION,
        services={
            "threat_orchestrator": {"status": "running"},
        },
    )
