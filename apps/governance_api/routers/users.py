"""User management CRUD endpoints."""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from apps.governance_api.dependencies import get_db, get_current_user, get_rbac
from apps.governance_api.utils.audit import record_audit
from shared.database.models.users import User
from shared.schemas.governance import (
    UserCreate,
    UserResponse,
    UserUpdate,
    UserListResponse,
)
from shared.security.rbac import Permission, RBACGuard, UserContext

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["users"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def check_permission(user: UserContext, permission: Permission, guard: RBACGuard):
    if not guard.has_permission(user, permission):
        raise HTTPException(status_code=403, detail=f"Permission {permission} required")


@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_USERS, guard)
    query = select(User)

    if role:
        query = query.where(User.role == role)
    if is_active is not None:
        query = query.where(User.is_active == is_active)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size).order_by(User.created_at.desc())
    users = (await db.execute(query)).scalars().all()

    await record_audit(db, user, "list", "user")

    return UserListResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_USERS, guard)
    user_data = await db.get(User, user_id)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    await record_audit(db, user, "view", "user", user_id)
    return UserResponse.model_validate(user_data)


@router.post("/", response_model=UserResponse, status_code=201)
async def create_user(
    request: UserCreate,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_USERS, guard)
    existing = await db.execute(
        select(User).where((User.username == request.username) | (User.email == request.email)),
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    user_obj = User(
        email=request.email,
        username=request.username,
        hashed_password=pwd_context.hash(request.password),
        full_name=request.full_name,
        role=request.role,
    )
    db.add(user_obj)
    await db.flush()
    await db.refresh(user_obj)
    await record_audit(db, user, "create", "user", str(user_obj.id))
    return UserResponse.model_validate(user_obj)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    request: UserUpdate,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_USERS, guard)
    user_obj = await db.get(User, user_id)
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = request.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user_obj, key, value)

    await db.flush()
    await db.refresh(user_obj)
    await record_audit(db, user, "update", "user", user_id)
    return UserResponse.model_validate(user_obj)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserContext = Depends(get_current_user),
    guard: RBACGuard = Depends(get_rbac),
):
    check_permission(user, Permission.MANAGE_USERS, guard)
    user_obj = await db.get(User, user_id)
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user_obj)
    await db.flush()
    await record_audit(db, user, "delete", "user", user_id)
