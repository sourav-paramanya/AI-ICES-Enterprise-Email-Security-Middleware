"""URL scanning endpoints."""

from typing import Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from services.url_protection.service import get_url_protection_service

router = APIRouter(prefix="/api/v1", tags=["url"])


class ScanUrlRequest(BaseModel):
    url: str
    message_id: Optional[str] = None


class ReputationResult(BaseModel):
    url: str
    is_malicious: bool
    score: float
    reasons: List[str]
    source: str


class ScanUrlResponse(BaseModel):
    message_id: Optional[str] = None
    original_url: str
    rewritten_url: str
    reputation: ReputationResult


class ExtractUrlsRequest(BaseModel):
    text: str
    message_id: Optional[str] = None


class ExtractUrlsResponse(BaseModel):
    message_id: Optional[str] = None
    urls: List[str]
    url_count: int


@router.post(
    "/scan-url",
    response_model=ScanUrlResponse,
    summary="Scan a single URL for threats",
)
async def scan_url(request: ScanUrlRequest):
    service = get_url_protection_service()

    _, rewritten = service.encrypt_url(request.url)
    reputation = await service.check_reputation(request.url)

    return ScanUrlResponse(
        message_id=request.message_id,
        original_url=request.url,
        rewritten_url=rewritten,
        reputation=ReputationResult(
            url=reputation["url"],
            is_malicious=reputation["is_malicious"],
            score=reputation["score"],
            reasons=reputation["reasons"],
            source=reputation["source"],
        ),
    )


@router.post(
    "/extract-urls",
    response_model=ExtractUrlsResponse,
    summary="Extract URLs from text content",
)
async def extract_urls(request: ExtractUrlsRequest):
    service = get_url_protection_service()
    urls = service.extract_urls(request.text)

    return ExtractUrlsResponse(
        message_id=request.message_id,
        urls=urls,
        url_count=len(urls),
    )
