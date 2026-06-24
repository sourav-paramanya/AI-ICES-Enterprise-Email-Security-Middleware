"""Role management CRUD endpoints."""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.governance_api.dependencies import get_db, get_current_user, get_rbac
from shared.database.models.users import Role as DB_Role
from shared.schemas.governance import (
    RoleCreate,
    RoleUpdate,
    RoleResponse,
)
from shared.security.rbac import Permission, RBACGuard, UserContext

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/roles", tags=["roles"])


def check_permission(user: UserContext, permission: Permission, guard: RBACGuard):
    if not guard.has_permission(user, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission {permission} required",
        )


@router.get("/", response_model=List[RoleResponse])
async def list_roles(
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_ROLES, guard)
    result = await db.execute(select(DB_Role))
    roles = result.scalars().all()
    return [RoleResponse.model_validate(r) for r in roles]


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_ROLES, guard)
    role = await db.get(DB_Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return RoleResponse.model_validate(role)


@router.post("/", response_model=RoleResponse, status_code=201)
async def create_role(
    request: RoleCreate,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_ROLES, guard)
    existing = await db.execute(select(DB_Role).where(DB_Role.name == request.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Role name already exists")

    role = DB_Role(
        name=request.name,
        description=request.description,
        permissions=request.permissions,
    )
    db.add(role)
    await db.flush()
    await db.refresh(role)
    return RoleResponse.model_validate(role)


@router.put("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    request: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_ROLES, guard)
    role = await db.get(DB_Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    update_data = request.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(role, key, value)

    await db.flush()
    await db.refresh(role)
    return RoleResponse.model_validate(role)


@router.delete("/{role_id}", status_code=204)
async def delete_role(
    role_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_ROLES, guard)
    role = await db.get(DB_Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    await db.delete(role)
    await db.flush()
