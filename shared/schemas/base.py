from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ServiceInfo(BaseModel):
    name: str
    status: HealthStatus
    version: str
    uptime_seconds: Optional[float] = None
    details: Optional[Dict[str, Any]] = None


class HealthCheck(BaseModel):
    status: HealthStatus
    version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    services: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def ok(cls, version: str, services: Optional[Dict[str, Any]] = None) -> "HealthCheck":
        return cls(
            status=HealthStatus.HEALTHY,
            version=version,
            services=services or {},
        )

    @classmethod
    def degraded(cls, version: str, services: Dict[str, Any]) -> "HealthCheck":
        return cls(
            status=HealthStatus.DEGRADED,
            version=version,
            services=services,
        )


class Message(BaseModel):
    detail: str
    code: Optional[str] = None


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int

    @classmethod
    def create(cls, items: List[T], total: int, page: int, page_size: int) -> "PaginatedResponse[T]":
        return cls(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=max(1, (total + page_size - 1) // page_size),
        )
