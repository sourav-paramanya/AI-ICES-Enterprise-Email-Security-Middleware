from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class Role(str, Enum):
    SUPER_ADMIN = "super_admin"
    SOC_ANALYST = "soc_analyst"
    AUDITOR = "auditor"
    HELPDESK = "helpdesk"


class Permission(str, Enum):
    # Threat Management
    VIEW_THREATS = "view:threats"
    QUARANTINE_EMAIL = "action:quarantine"
    DELETE_EMAIL = "action:delete"
    RESTORE_EMAIL = "action:restore"
    RELEASE_FALSE_POSITIVE = "action:release_false_positive"

    # URL Protection
    VIEW_URL_ANALYTICS = "view:url_analytics"
    MANAGE_URL_BLOCKLIST = "manage:url_blocklist"

    # Audit
    VIEW_AUDIT_LOGS = "view:audit_logs"
    EXPORT_AUDIT_LOGS = "export:audit_logs"

    # Administration
    MANAGE_USERS = "manage:users"
    MANAGE_ROLES = "manage:roles"
    MANAGE_SYSTEM_CONFIG = "manage:system_config"
    VIEW_SYSTEM_HEALTH = "view:system_health"

    # Remediation
    EXECUTE_REMEDIATION = "execute:remediation"
    VIEW_REMEDIATION_HISTORY = "view:remediation_history"


class UserContext(BaseModel):
    user_id: str
    username: str
    email: str
    role: Role
    permissions: List[Permission] = []
    is_authenticated: bool = True


class RBACGuard:
    def __init__(self) -> None:
        self._role_permissions: Dict[Role, List[Permission]] = self._build_role_map()

    def _build_role_map(self) -> Dict[Role, List[Permission]]:
        return {
            Role.SUPER_ADMIN: list(Permission),
            Role.SOC_ANALYST: [
                Permission.VIEW_THREATS,
                Permission.QUARANTINE_EMAIL,
                Permission.DELETE_EMAIL,
                Permission.RESTORE_EMAIL,
                Permission.RELEASE_FALSE_POSITIVE,
                Permission.VIEW_URL_ANALYTICS,
                Permission.VIEW_AUDIT_LOGS,
                Permission.VIEW_REMEDIATION_HISTORY,
                Permission.EXECUTE_REMEDIATION,
            ],
            Role.AUDITOR: [
                Permission.VIEW_THREATS,
                Permission.VIEW_URL_ANALYTICS,
                Permission.VIEW_AUDIT_LOGS,
                Permission.EXPORT_AUDIT_LOGS,
                Permission.VIEW_REMEDIATION_HISTORY,
                Permission.VIEW_SYSTEM_HEALTH,
            ],
            Role.HELPDESK: [
                Permission.VIEW_THREATS,
                Permission.RELEASE_FALSE_POSITIVE,
                Permission.VIEW_REMEDIATION_HISTORY,
            ],
        }

    def has_permission(self, user: UserContext, permission: Permission) -> bool:
        return permission in user.permissions

    def has_role(self, user: UserContext, role: Role) -> bool:
        return user.role == role

    def get_role_permissions(self, role: Role) -> List[Permission]:
        return self._role_permissions.get(role, [])


@lru_cache
def get_rbac_guard() -> RBACGuard:
    return RBACGuard()


def require_role(required_role: Role):
    def decorator(user_context: UserContext) -> bool:
        return user_context.role == required_role
    return decorator


def require_permission(required_permission: Permission):
    def decorator(user_context: UserContext) -> bool:
        guard = get_rbac_guard()
        return guard.has_permission(user_context, required_permission)
    return decorator
