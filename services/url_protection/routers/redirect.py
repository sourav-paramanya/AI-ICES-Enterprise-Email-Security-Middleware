"""Time-of-click URL redirect gateway."""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, HTMLResponse

from services.url_protection.service import get_url_protection_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["redirect"])

BLOCK_PAGE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Access Blocked - AI-ICES</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
    <h1 style="color: #d32f2f;">Security Warning</h1>
    <p>The URL you clicked has been blocked by AI-ICES security.</p>
    <p>This link was detected as potentially malicious.</p>
    <hr>
    <p style="color: #666;">If you believe this is a false positive, contact your SOC team.</p>
</body>
</html>
"""


@router.get("/redirect", summary="Time-of-click URL redirect")
async def redirect_url(
    token: str = Query(..., description="Encrypted URL token"),
    request: Optional[Request] = None,
):
    service = get_url_protection_service()

    try:
        original_url = service.decrypt_url(token)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired redirect token",
        )

    # Check URL reputation at time of click
    reputation = await service.check_reputation(original_url)

    # Log the click
    from shared.database.session import async_session_factory
    from shared.database.models.url_click_logs import UrlClickLog

    try:
        click_log = UrlClickLog(
            original_url=original_url,
            rewritten_url=f"/redirect?token={token[:20]}...",
            redirect_token=token,
            clicked_by=request.client.host if request else None,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None,
            reputation_status="malicious" if reputation["is_malicious"] else "safe",
            verdict="block" if reputation["is_malicious"] else "allow",
            threat_score=reputation["score"],
            threat_intel_data=reputation,
            block_reason=", ".join(reputation["reasons"]) if reputation["is_malicious"] else None,
        )

        async with async_session_factory() as session:
            session.add(click_log)
            await session.commit()

    except Exception as e:
        logger.error("Failed to log URL click: %s", str(e))

    if reputation["is_malicious"]:
        logger.warning(
            "Blocked malicious URL click: %s (score=%.2f)",
            original_url,
            reputation["score"],
        )
        return HTMLResponse(content=BLOCK_PAGE_HTML, status_code=403)

    logger.info("Redirecting to safe URL: %s", original_url[:100])
    return RedirectResponse(url=original_url, status_code=302)
