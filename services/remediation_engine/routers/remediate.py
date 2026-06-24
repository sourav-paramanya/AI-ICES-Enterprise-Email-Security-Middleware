"""Remediation API endpoints for manual SOC operations."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.remediation_engine.clawback import get_zimbra_client

router = APIRouter(prefix="/api/v1", tags=["remediation"])


class SearchRequest(BaseModel):
    query: str
    limit: int = 50
    account_email: Optional[str] = None


class RemediateRequest(BaseModel):
    message_id: str
    account_email: str
    action: str  # quarantine, delete, restore
    session_id: Optional[str] = None


class RemediateResponse(BaseModel):
    status: str
    message_id: str
    action: str
    details: Dict[str, Any]


@router.post(
    "/search",
    summary="Search for emails in Zimbra mailbox",
)
async def search_emails(request: SearchRequest):
    client = get_zimbra_client()
    await client.initialize()
    try:
        await client.authenticate()
        matches = await client.search_email(request.query, request.limit, request.account_email)
        return {"results": matches, "count": len(matches)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Zimbra search failed: {str(e)}")
    finally:
        await client.close()


@router.post(
    "/remediate",
    response_model=RemediateResponse,
    summary="Execute remediation action on an email",
)
async def remediate_email(request: RemediateRequest):
    if request.action not in ("quarantine", "delete", "restore"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {request.action}. Must be: quarantine, delete, restore",
        )

    client = get_zimbra_client()
    await client.initialize()

    try:
        await client.authenticate()

        if request.action == "quarantine":
            result = await client.move_to_quarantine(request.message_id, request.account_email)
        elif request.action == "delete":
            result = await client.delete_email(request.message_id, request.account_email)
        elif request.action == "restore":
            result = await client.restore_email(request.message_id, request.account_email)
        else:
            raise ValueError(f"Unknown action: {request.action}")

        return RemediateResponse(
            status="success",
            message_id=request.message_id,
            action=request.action,
            details=result,
        )

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Remediation failed: {str(e)}")
    finally:
        await client.close()
