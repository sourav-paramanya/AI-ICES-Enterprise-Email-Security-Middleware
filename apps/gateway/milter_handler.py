"""Milter-based email interception handler.

Receives SMTP transactions from Zimbra Postfix Milter,
extracts email content, and forwards payloads to Core Hub.
"""

import email
import json
import logging
import time
import uuid
from email.mime.base import MIMEBase
from io import BytesIO
from typing import Any, Dict, List, Optional

import httpx
import Milter
from Milter.utils import parse_addr

from shared.config.settings import get_settings

logger = logging.getLogger(__name__)


class EmailInterceptionHandler(Milter.Base):
    """Milter handler that intercepts and forwards email to Core Hub."""

    def __init__(self) -> None:
        self.session_id: str = str(uuid.uuid4())
        self.message_id: Optional[str] = None
        self.headers: Dict[str, str] = {}
        self.recipients: List[str] = []
        self.sender: Optional[str] = None
        self.body_parts: List[bytes] = []
        self.attachment_metadata: List[Dict[str, Any]] = []
        self.start_time: float = 0.0
        self.email_size: int = 0
        self._settings = get_settings()
        self._core_hub_url: str = (
            f"http://{self._settings.CORE_HUB_HOST or 'localhost'}:"
            f"{self._settings.CORE_HUB_PORT}/api/v1/ingest"
        )

    @Milter.noreply
    def connect(self, hostname: str, family: int, hostaddr: Any) -> int:
        self.start_time = time.time()
        logger.info(
            "Milter connection from %s (%s) session=%s",
            hostname,
            hostaddr,
            self.session_id,
        )
        return Milter.CONTINUE

    @Milter.noreply
    def helo(self, hostname: str) -> int:
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, address: Any, *params: Any) -> int:
        try:
            self.sender = str(parse_addr(str(address))[1])
        except Exception:
            self.sender = str(address)
        logger.debug("Mail from: %s", self.sender)
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, address: Any, *params: Any) -> int:
        try:
            rcpt = str(parse_addr(str(address))[1])
        except Exception:
            rcpt = str(address)
        self.recipients.append(rcpt)
        logger.debug("Rcpt to: %s", rcpt)
        return Milter.CONTINUE

    def header(self, name: str, hval: str) -> int:
        self.headers[name] = hval
        if name.lower() == "message-id":
            self.message_id = hval.strip("<>")
        return Milter.CONTINUE

    def eoh(self) -> int:
        return Milter.CONTINUE

    def body(self, chunk: bytes) -> int:
        self.body_parts.append(chunk)
        self.email_size += len(chunk)
        return Milter.CONTINUE

    def eom(self) -> int:
        """End of message - parse and forward to Core Hub."""
        elapsed = int((time.time() - self.start_time) * 1000)
        logger.info(
            "EOM session=%s size=%d bytes elapsed=%dms",
            self.session_id,
            self.email_size,
            elapsed,
        )

        try:
            raw_email = b"".join(self.body_parts)
            parsed = email.message_from_bytes(raw_email)

            body_text, body_html, attachments = self._parse_email_parts(parsed)

            payload = {
                "session_id": self.session_id,
                "message_id": self.message_id or f"generated-{self.session_id}",
                "sender": self.sender or "unknown",
                "recipients": self.recipients,
                "subject": self.headers.get("Subject", ""),
                "body_text": body_text,
                "body_html": body_html,
                "headers": self.headers,
                "attachments": attachments,
                "email_size": self.email_size,
            }

            self._forward_to_core_hub(payload, elapsed)

        except Exception as e:
            logger.error(
                "Failed to process email session=%s error=%s",
                self.session_id,
                str(e),
                exc_info=True,
            )

        return Milter.CONTINUE

    def _parse_email_parts(self, msg: email.message.Message) -> tuple:
        """Extract text body and attachment metadata from parsed email."""
        body_text: Optional[str] = None
        body_html: Optional[str] = None
        attachments: List[Dict[str, Any]] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition or part.get_content_maintype() not in ("text", "multipart"):
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            "filename": filename,
                            "content_type": content_type,
                            "size": len(part.get_payload(decode=True) or b""),
                            "content_id": part.get("Content-ID"),
                            "is_inline": "inline" in content_disposition,
                        })
                    continue

                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = part.get_payload(decode=True)
                    if decoded:
                        decoded_str = decoded.decode(charset, errors="replace")
                        if content_type == "text/plain":
                            body_text = (body_text or "") + decoded_str
                        elif content_type == "text/html":
                            body_html = (body_html or "") + decoded_str
                except Exception:
                    pass
        else:
            content_type = msg.get_content_type()
            charset = msg.get_content_charset() or "utf-8"
            try:
                decoded = msg.get_payload(decode=True)
                if decoded:
                    decoded_str = decoded.decode(charset, errors="replace")
                    if content_type == "text/plain":
                        body_text = decoded_str
                    elif content_type == "text/html":
                        body_html = decoded_str
                    else:
                        body_text = decoded_str
            except Exception:
                pass

        return body_text, body_html, attachments

    def _forward_to_core_hub(self, payload: Dict[str, Any], elapsed_ms: int) -> None:
        """Forward parsed email payload to Core Hub asynchronously."""
        try:
            import threading

            def _send() -> None:
                try:
                    with httpx.Client(timeout=5.0) as client:
                        response = client.post(
                            self._core_hub_url,
                            json=payload,
                            headers={"Content-Type": "application/json"},
                        )
                        if response.is_success:
                            logger.info(
                                "Forwarded session=%s to Core Hub status=%s time=%dms",
                                self.session_id,
                                response.status_code,
                                int((time.time() - self.start_time) * 1000),
                            )
                        else:
                            logger.warning(
                                "Core Hub returned %s for session=%s: %s",
                                response.status_code,
                                self.session_id,
                                response.text[:200],
                            )
                except Exception as e:
                    logger.error(
                        "Failed to forward session=%s to Core Hub: %s",
                        self.session_id,
                        str(e),
                    )

            thread = threading.Thread(target=_send, daemon=True)
            thread.start()

        except Exception as e:
            logger.error(
                "Failed to spawn forward thread session=%s: %s",
                self.session_id,
                str(e),
            )


def start_milter_server() -> None:
    """Start the Milter listener daemon."""
    settings = get_settings()
    socket_spec = f"inet:{settings.GATEWAY_PORT}@{settings.MILTER_HOST}"

    logger.info(
        "Starting Milter server on %s timeout=%ds",
        socket_spec,
        settings.MILTER_TIMEOUT,
    )

    Milter.factory = EmailInterceptionHandler
    Milter.runmilter(
        "AI-ICES-Gateway",
        socket_spec,
        settings.MILTER_TIMEOUT,
    )
