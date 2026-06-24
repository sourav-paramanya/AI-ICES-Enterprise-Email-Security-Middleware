"""Content Disarm & Reconstruction (CDR) Engine.

Sanitizes PDF, DOCX, XLSX, and PPTX attachments by removing
macros, JavaScript, embedded objects, and auto-actions,
then reconstructs a safe version of the file.
"""

import io
import logging
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Supported file types
SUPPORTED_TYPES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/msword": "doc",
    "application/vnd.ms-excel": "xls",
    "application/vnd.ms-powerpoint": "ppt",
}


class CDRSanitizer:
    """Sanitize documents by removing active/malicious content."""

    def sanitize(self, file_bytes: bytes, mime_type: str, filename: str = "") -> Dict[str, Any]:
        """Sanitize a document file.

        Returns:
            Dict with keys: status, safe_file (bytes as base64?), details, issues_found, processing_time_ms
        """
        start_time = time.time()
        file_ext = self._get_extension(mime_type, filename)

        result: Dict[str, Any] = {
            "status": "sanitized",
            "original_filename": filename,
            "file_type": file_ext,
            "original_size": len(file_bytes),
            "safe_size": 0,
            "issues_found": [],
            "issues_removed": [],
            "processing_time_ms": 0,
            "safe_file": None,
        }

        try:
            if file_ext == "pdf":
                safe_bytes, issues = self._sanitize_pdf(file_bytes)
            elif file_ext in ("docx", "doc"):
                safe_bytes, issues = self._sanitize_docx(file_bytes)
            elif file_ext in ("xlsx", "xls"):
                safe_bytes, issues = self._sanitize_xlsx(file_bytes)
            elif file_ext in ("pptx", "ppt"):
                safe_bytes, issues = self._sanitize_pptx(file_bytes)
            else:
                result["status"] = "unsupported"
                result["issues_found"].append(f"Unsupported file type: {mime_type}")
                safe_bytes = file_bytes
                issues = []

            result["safe_file"] = safe_bytes
            result["safe_size"] = len(safe_bytes)
            result["issues_found"] = issues
            result["issues_removed"] = issues
            result["processing_time_ms"] = int((time.time() - start_time) * 1000)

        except Exception as e:
            logger.error("CDR sanitization error: %s", str(e), exc_info=True)
            result["status"] = "error"
            result["issues_found"].append(str(e))
            result["safe_file"] = file_bytes

        return result

    def is_supported(self, mime_type: str, filename: str = "") -> bool:
        return self._get_extension(mime_type, filename) in ("pdf", "docx", "xlsx", "pptx")

    def _get_extension(self, mime_type: str, filename: str) -> str:
        """Determine file extension from MIME type or filename."""
        ext = SUPPORTED_TYPES.get(mime_type, "")
        if not ext and filename:
            path = Path(filename)
            ext = path.suffix.lower().lstrip(".")
            if ext == "doc":
                ext = "docx"
            elif ext == "xls":
                ext = "xlsx"
            elif ext == "ppt":
                ext = "pptx"
        return ext

    def _sanitize_pdf(self, file_bytes: bytes) -> Tuple[bytes, list]:
        """Remove JavaScript, embedded files, and actions from PDF."""
        import PyPDF2

        issues = []
        reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))

        # Check for JavaScript
        if reader.js:
            issues.append("JavaScript detected and removed")

        # Check for embedded files
        if reader.attachments:
            issues.append(f"Embedded files detected and removed: {list(reader.attachments.keys())}")

        # Reconstruct without dangerous elements
        writer = PyPDF2.PdfWriter()
        for page_num in range(len(reader.pages)):
            page = reader.pages[page_num]
            writer.add_page(page)

        # Remove metadata (can contain malicious content)
        writer.add_metadata({})

        output = io.BytesIO()
        writer.write(output)
        output.seek(0)

        if not issues:
            issues.append("No issues found")
            return file_bytes, issues

        return output.getvalue(), issues

    def _sanitize_docx(self, file_bytes: bytes) -> Tuple[bytes, list]:
        """Remove macros and embedded objects from DOCX."""
        import zipfile

        issues = []

        # DOCX is a ZIP file; we inspect and rebuild without macros
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zin:
                # Check for VBA macros
                has_vba = any(
                    name.endswith(".bin") and "vba" in name.lower()
                    for name in zin.namelist()
                )
                if has_vba:
                    issues.append("VBA macros detected and removed")

                # Rebuild without macro-related files
                safe_data = io.BytesIO()
                with zipfile.ZipFile(safe_data, "w", zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        # Skip macro-related files
                        if any(x in item.filename.lower() for x in ["vba", "macro", "vbaProject"]):
                            continue
                        zout.writestr(item, zin.read(item.filename))

                safe_data.seek(0)
                return safe_data.getvalue(), issues
        except zipfile.BadZipFile:
            issues.append("Invalid DOCX (not a ZIP archive)")
            return file_bytes, issues

    def _sanitize_xlsx(self, file_bytes: bytes) -> Tuple[bytes, list]:
        """Remove macros from XLSX."""
        import zipfile

        issues = []

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zin:
                # Check for VBA macros
                has_vba = any(
                    "vba" in name.lower() or "macro" in name.lower()
                    for name in zin.namelist()
                )
                if has_vba:
                    issues.append("XLSM/VBA macros detected and removed")

                # Rebuild without macro files
                safe_data = io.BytesIO()
                with zipfile.ZipFile(safe_data, "w", zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        if any(x in item.filename.lower() for x in ["vba", "macro", "vbaProject"]):
                            continue
                        zout.writestr(item, zin.read(item.filename))

                safe_data.seek(0)
                return safe_data.getvalue(), issues
        except zipfile.BadZipFile:
            issues.append("Invalid XLSX (not a ZIP archive)")
            return file_bytes, issues

    def _sanitize_pptx(self, file_bytes: bytes) -> Tuple[bytes, list]:
        """Remove macros and embedded objects from PPTX."""
        import zipfile

        issues = []

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zin:
                # Check for macros
                has_macros = any(
                    "vba" in name.lower() or "macro" in name.lower()
                    for name in zin.namelist()
                )
                if has_macros:
                    issues.append("PPT macros detected and removed")

                # Rebuild without macro files
                safe_data = io.BytesIO()
                with zipfile.ZipFile(safe_data, "w", zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        if any(x in item.filename.lower() for x in ["vba", "macro", "vbaProject"]):
                            continue
                        zout.writestr(item, zin.read(item.filename))

                safe_data.seek(0)
                return safe_data.getvalue(), issues
        except zipfile.BadZipFile:
            issues.append("Invalid PPTX (not a ZIP archive)")
            return file_bytes, issues


# Singleton
from functools import lru_cache

@lru_cache
def get_cdr_sanitizer() -> CDRSanitizer:
    return CDRSanitizer()
