"""Computer vision engine for image-based threat detection.

Uses PaddleOCR v5 for text extraction, OpenCV for image processing,
and PyZbar for QR/barcode decoding.
"""

import io
import logging
import re
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)

# QR code URL pattern for validating decoded QR content
URL_PATTERN = re.compile(
    r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
    r"(?:/[-\w$.+!*'(),;:@&=?~#%]*)?",
    re.IGNORECASE,
)


class VisionProcessor:
    """Process images for OCR text extraction and QR code detection."""

    def __init__(self) -> None:
        self._ocr_engine = None
        self._loaded = False

    def load_engine(self) -> None:
        """Initialize the OCR engine and QR decoder."""
        try:
            self._load_paddle_ocr()
        except Exception as e:
            logger.warning("Failed to load PaddleOCR: %s, using Tesseract fallback", e)
            try:
                self._load_tesseract()
            except Exception as e2:
                logger.warning("Failed to load Tesseract: %s", e2)
                self._loaded = False
                return
        self._loaded = True
        logger.info("Vision engine loaded successfully")

    def _load_paddle_ocr(self) -> None:
        """Initialize PaddleOCR engine."""
        try:
            from paddleocr import PaddleOCR

            self._ocr_engine = PaddleOCR(
                use_angle_cls=True,
                lang="en",
                use_gpu=False,
                show_log=False,
            )
            logger.info("PaddleOCR initialized")
        except ImportError:
            raise ImportError("PaddleOCR is not installed")

    def _load_tesseract(self) -> None:
        """Fallback to Tesseract OCR."""
        try:
            import pytesseract
            self._ocr_engine = pytesseract
            logger.info("Tesseract OCR initialized as fallback")
        except ImportError:
            raise ImportError("Neither PaddleOCR nor pytesseract are available")

    def process_image(self, image_bytes: bytes) -> Dict[str, Any]:
        """Process an image for OCR text and QR codes."""
        start_time = time.time()
        result: Dict[str, Any] = {
            "detected_urls": [],
            "ocr_text": "",
            "qr_codes": [],
            "has_qr": False,
            "has_text": False,
            "image_phishing_score": 0.0,
            "processing_time_ms": 0,
        }

        try:
            # Decode image
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            if img is None:
                # Try PIL as fallback
                pil_img = Image.open(io.BytesIO(image_bytes))
                img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

            # Extract text via OCR
            ocr_text = self._extract_text(img)
            result["ocr_text"] = ocr_text
            result["has_text"] = bool(ocr_text.strip())

            # Extract URLs from OCR text
            if ocr_text:
                urls = URL_PATTERN.findall(ocr_text)
                result["detected_urls"] = list(set(urls))

            # Detect QR codes
            qr_results = self._detect_qr_codes(img)
            result["qr_codes"] = qr_results
            result["has_qr"] = len(qr_results) > 0

            # Add QR URLs to detected URLs
            for qr in qr_results:
                if qr.get("url"):
                    result["detected_urls"].append(qr["url"])

            # Calculate image phishing score
            result["image_phishing_score"] = self._calculate_phishing_score(
                result["detected_urls"],
                result["has_qr"],
            )

            result["processing_time_ms"] = int((time.time() - start_time) * 1000)

        except Exception as e:
            logger.error("Image processing error: %s", str(e), exc_info=True)
            result["error"] = str(e)

        return result

    def _extract_text(self, img: np.ndarray) -> str:
        """Extract text from image using OCR."""
        if not self._loaded or self._ocr_engine is None:
            return ""

        try:
            if hasattr(self._ocr_engine, "ocr"):
                # PaddleOCR
                result = self._ocr_engine.ocr(img, cls=True)
                if result and result[0]:
                    lines = []
                    for line in result[0]:
                        if line and len(line) > 1:
                            text = line[1][0] if len(line[1]) > 0 else ""
                            confidence = line[1][1] if len(line[1]) > 1 else 0
                            if confidence > 0.5:
                                lines.append(text)
                    return "\n".join(lines)
            else:
                # Tesseract fallback
                rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                text = self._ocr_engine.image_to_string(rgb)
                return text.strip()
        except Exception as e:
            logger.error("OCR extraction error: %s", str(e))
            return ""

    def _detect_qr_codes(self, img: np.ndarray) -> List[Dict[str, Any]]:
        """Detect and decode QR codes in image."""
        qr_results: List[Dict[str, Any]] = []

        try:
            from pyzbar.pyzbar import decode as pyzbar_decode

            decoded_objects = pyzbar_decode(img)
            for obj in decoded_objects:
                qr_data = obj.data.decode("utf-8", errors="replace")
                qr_type = obj.type

                entry: Dict[str, Any] = {
                    "data": qr_data,
                    "type": qr_type,
                    "url": None,
                }

                # Check if QR contains a URL
                url_match = URL_PATTERN.search(qr_data)
                if url_match:
                    entry["url"] = url_match.group(0)

                qr_results.append(entry)

            # Also try OpenCV QR detector for better coverage
            qr_detector = cv2.QRCodeDetector()
            retval, decoded_info, points, straight_qrcode = qr_detector.detectAndDecodeMulti(img)

            if retval and decoded_info:
                existing_data = {qr["data"] for qr in qr_results}
                for info in decoded_info:
                    if info and info not in existing_data:
                        entry: Dict[str, Any] = {
                            "data": info,
                            "type": "QRCODE",
                            "url": None,
                        }
                        url_match = URL_PATTERN.search(info)
                        if url_match:
                            entry["url"] = url_match.group(0)
                        qr_results.append(entry)

        except ImportError:
            logger.warning("PyZbar not available, using OpenCV QR detector only")
            qr_detector = cv2.QRCodeDetector()
            retval, decoded_info, *_ = qr_detector.detectAndDecode(img)
            if retval and decoded_info:
                entry: Dict[str, Any] = {
                    "data": decoded_info,
                    "type": "QRCODE",
                    "url": None,
                }
                url_match = URL_PATTERN.search(decoded_info)
                if url_match:
                    entry["url"] = url_match.group(0)
                qr_results.append(entry)

        except Exception as e:
            logger.error("QR detection error: %s", str(e))

        return qr_results

    def _calculate_phishing_score(self, detected_urls: List[str], has_qr: bool) -> float:
        """Calculate a heuristic phishing score based on findings."""
        score = 0.0

        if has_qr:
            score += 0.3

        if detected_urls:
            suspicious_count = 0
            for url in detected_urls:
                url_lower = url.lower()
                if any(domain in url_lower for domain in [
                    "bit.ly", "tinyurl", "shorturl", "rb.gy", "short.link",
                    "login", "verify", "account", "secure", "banking",
                ]):
                    suspicious_count += 1

            if suspicious_count > 0:
                score += min(0.4 * (suspicious_count / len(detected_urls)), 0.4)

            if len(detected_urls) > 2:
                score += 0.1

            # Check for HTTPS vs HTTP
            non_https = sum(1 for url in detected_urls if not url.startswith("https://"))
            if non_https > 0:
                score += 0.1 * (non_https / len(detected_urls))

        return min(score, 1.0)


@lru_cache
def get_vision_processor() -> VisionProcessor:
    processor = VisionProcessor()
    processor.load_engine()
    return processor
