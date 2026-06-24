"""CDR sanitization endpoints."""

import base64
from typing import List, Optional

from fastapi import APIRouter, HTTPException, UploadFile
from pydantic import BaseModel

from services.cdr_engine.sanitizer import get_cdr_sanitizer

router = APIRouter(prefix="/api/v1", tags=["cdr"])


class SanitizeRequest(BaseModel):
    file_base64: str
    mime_type: str
    filename: Optional[str] = None
    message_id: Optional[str] = None


class SanitizeResponse(BaseModel):
    message_id: Optional[str] = None
    status: str
    original_filename: str
    file_type: str
    original_size: int
    safe_size: int
    issues_found: List[str]
    processing_time_ms: int
    safe_file_base64: Optional[str] = None


@router.post(
    "/sanitize",
    response_model=SanitizeResponse,
    summary="Sanitize a document file",
    description="Remove macros, scripts, and embedded objects from PDF/DOCX/XLSX/PPTX",
)
async def sanitize_file(request: SanitizeRequest):
    try:
        file_bytes = base64.b64decode(request.file_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")

    sanitizer = get_cdr_sanitizer()
    result = sanitizer.sanitize(file_bytes, request.mime_type, request.filename or "unknown")

    safe_b64 = None
    if result.get("safe_file"):
        safe_b64 = base64.b64encode(result["safe_file"]).decode()

    return SanitizeResponse(
        message_id=request.message_id,
        status=result["status"],
        original_filename=result.get("original_filename", request.filename or "unknown"),
        file_type=result.get("file_type", "unknown"),
        original_size=result.get("original_size", 0),
        safe_size=result.get("safe_size", 0),
        issues_found=result.get("issues_found", []),
        processing_time_ms=result.get("processing_time_ms", 0),
        safe_file_base64=safe_b64,
    )


@router.post(
    "/sanitize/upload",
    response_model=SanitizeResponse,
    summary="Sanitize an uploaded document file",
)
async def sanitize_upload(
    file: UploadFile,
    message_id: Optional[str] = None,
):
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")

    sanitizer = get_cdr_sanitizer()
    result = sanitizer.sanitize(contents, file.content_type or "", file.filename or "unknown")

    safe_b64 = None
    if result.get("safe_file"):
        safe_b64 = base64.b64encode(result["safe_file"]).decode()

    return SanitizeResponse(
        message_id=message_id,
        status=result["status"],
        original_filename=result.get("original_filename", file.filename or "unknown"),
        file_type=result.get("file_type", "unknown"),
        original_size=result.get("original_size", 0),
        safe_size=result.get("safe_size", 0),
        issues_found=result.get("issues_found", []),
        processing_time_ms=result.get("processing_time_ms", 0),
        safe_file_base64=safe_b64,
    )
