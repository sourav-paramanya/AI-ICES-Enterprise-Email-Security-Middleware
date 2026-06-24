import base64
from typing import List, Optional

from fastapi import APIRouter, HTTPException, UploadFile
from pydantic import BaseModel

from services.vision_engine.processor import get_vision_processor

router = APIRouter(prefix="/api/v1", tags=["vision"])


class ScanRequest(BaseModel):
    message_id: str
    image_base64: str
    filename: Optional[str] = None


class QrCodeInfo(BaseModel):
    data: str
    type: str
    url: Optional[str] = None


class ScanResponse(BaseModel):
    message_id: str
    detected_urls: List[str]
    ocr_text: str
    qr_codes: List[QrCodeInfo]
    has_qr: bool
    has_text: bool
    image_phishing_score: float
    processing_time_ms: int


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Scan image for threats",
    description="Extract OCR text and QR codes from image for threat analysis",
)
async def scan_image(request: ScanRequest):
    if not request.image_base64:
        raise HTTPException(status_code=400, detail="No image data provided")

    try:
        image_bytes = base64.b64decode(request.image_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 image data")

    processor = get_vision_processor()
    result = processor.process_image(image_bytes)

    return ScanResponse(
        message_id=request.message_id,
        detected_urls=result.get("detected_urls", []),
        ocr_text=result.get("ocr_text", ""),
        qr_codes=[QrCodeInfo(**qr) for qr in result.get("qr_codes", [])],
        has_qr=result.get("has_qr", False),
        has_text=result.get("has_text", False),
        image_phishing_score=result.get("image_phishing_score", 0.0),
        processing_time_ms=result.get("processing_time_ms", 0),
    )


@router.post(
    "/scan/upload",
    response_model=ScanResponse,
    summary="Scan uploaded image file",
)
async def scan_image_upload(
    message_id: str,
    file: UploadFile,
):
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")

    processor = get_vision_processor()
    result = processor.process_image(contents)

    return ScanResponse(
        message_id=message_id,
        detected_urls=result.get("detected_urls", []),
        ocr_text=result.get("ocr_text", ""),
        qr_codes=[QrCodeInfo(**qr) for qr in result.get("qr_codes", [])],
        has_qr=result.get("has_qr", False),
        has_text=result.get("has_text", False),
        image_phishing_score=result.get("image_phishing_score", 0.0),
        processing_time_ms=result.get("processing_time_ms", 0),
    )
