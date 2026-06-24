from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field


# ── Auth ───────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


# ── Users ──────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: str
    username: str
    password: str
    full_name: Optional[str] = None
    role: str = "soc_analyst"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    is_locked: bool
    mfa_enabled: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    items: List[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ── Roles ──────────────────────────────────────────────────────────────
class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: List[str] = []


class RoleUpdate(BaseModel):
    description: Optional[str] = None
    permissions: Optional[List[str]] = None


class RoleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    permissions: List[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ── Audit ──────────────────────────────────────────────────────────────
class AuditLogResponse(BaseModel):
    id: str
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    actor_role: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ── Dashboard ──────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_emails_processed: int
    threats_detected: int
    remediations_performed: int
    url_clicks_blocked: int
    average_scan_time_ms: float
    clawback_success_rate: float
    threats_by_type: Dict[str, int]
    emails_over_time: List[Dict[str, Any]]


class ThreatResponse(BaseModel):
    id: str
    email_log_id: str
    threat_type: str
    threat_score: float
    verdict: str
    detected_at: datetime
    nlp_label: Optional[str] = None
    vision_label: Optional[str] = None
    url_verdict: Optional[str] = None
    cdr_status: Optional[str] = None

    class Config:
        from_attributes = True


class ThreatListResponse(BaseModel):
    items: List[ThreatResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class RemediationResponse(BaseModel):
    id: str
    email_log_id: str
    action: str
    status: str
    initiated_by: Optional[str] = None
    initiated_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class RemediationListResponse(BaseModel):
    items: List[RemediationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
