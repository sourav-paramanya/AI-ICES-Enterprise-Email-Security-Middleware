"""URL Protection Service.

Provides URL rewriting via Fernet encryption, time-of-click redirect gateway,
and live threat intelligence validation.
"""

import logging
import re
import time
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import httpx
from cryptography.fernet import Fernet

from shared.config.settings import get_settings
from shared.redis import get_redis_client

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w$.+!*'(),;:@&=?~#%]*)*",
    re.IGNORECASE,
)

# Known suspicious patterns
SUSPICIOUS_PATTERNS = [
    r"login\.\w+\.\w+",
    r"secure\.\w+\.\w+",
    r"account\.\w+\.\w+",
    r"verify\.\w+",
    r"update\.\w+",
    r"signin\.\w+",
    r"paypal.*verify",
    r"bank.*secure",
    r"bit\.ly",
    r"tinyurl\.com",
    r"shorturl\.at",
    r"rb\.gy",
    r"short\.link",
    r"ow\.ly",
    r"is\.gd",
    r"buff\.ly",
    r"shorte\.st",
    r"adf\.ly",
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".work", ".date", ".men", ".loan"}


class URLProtectionService:
    """Core URL protection logic."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._fernet: Optional[Fernet] = None
        self._redis = get_redis_client()
        self._http_client: Optional[httpx.AsyncClient] = None

    async def initialize(self) -> None:
        """Initialize encryption keys and HTTP client."""
        key = self._settings.ENCRYPTION_KEY
        if len(key) != 44:
            key = Fernet.generate_key()
            logger.warning("Generated new Fernet key (configure ENCRYPTION_KEY for persistence)")
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

        self._http_client = httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            limits=httpx.Limits(max_keepalive_connections=10),
        )
        logger.info("URL Protection service initialized")

    async def close(self) -> None:
        if self._http_client:
            await self._http_client.aclose()

    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text content."""
        if not text:
            return []
        return list(set(URL_PATTERN.findall(text)))

    def encrypt_url(self, original_url: str) -> Tuple[str, str]:
        """Encrypt URL and return (token, rewritten_url)."""
        if not self._fernet:
            raise RuntimeError("Fernet not initialized")

        token_data = f"{original_url}|{uuid.uuid4()}|{datetime.now(timezone.utc).isoformat()}"
        token = self._fernet.encrypt(token_data.encode()).decode()

        rewritten_url = (
            f"{self._settings.URL_PROTECTION_BASE_URL or 'http://localhost:8300'}"
            f"/redirect?token={token}"
        )
        return token, rewritten_url

    def decrypt_url(self, token: str) -> str:
        """Decrypt token to get original URL."""
        if not self._fernet:
            raise RuntimeError("Fernet not initialized")

        try:
            decrypted = self._fernet.decrypt(token.encode()).decode()
            original_url = decrypted.split("|")[0]
            return original_url
        except Exception as e:
            logger.error("Failed to decrypt URL token: %s", str(e))
            raise ValueError("Invalid or expired token")

    async def check_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation via threat intelligence."""
        result: Dict[str, Any] = {
            "url": url,
            "is_malicious": False,
            "score": 0.0,
            "reasons": [],
            "source": "local",
        }

        # Local heuristic checks
        domain = self._extract_domain(url)

        # Check suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                result["reasons"].append(f"Matches suspicious pattern: {pattern}")
                result["score"] += 0.3

        # Check TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["reasons"].append(f"Suspicious TLD: {tld}")
                result["score"] += 0.2

        # Check if URL is HTTPS
        if not url.startswith("https://"):
            result["reasons"].append("Non-HTTPS URL")
            result["score"] += 0.1

        # Check for IP-based URLs
        ip_pattern = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        if ip_pattern.match(url):
            result["reasons"].append("IP-based URL (not domain)")
            result["score"] += 0.4

        # Check for excessive subdomains
        domain_parts = domain.split(".")
        if len(domain_parts) > 4:
            result["reasons"].append("Excessive subdomains")
            result["score"] += 0.2

        # External threat intelligence check (if configured)
        if self._settings.THREAT_INTEL_API_KEY and self._settings.THREAT_INTEL_API_URL:
            try:
                ext_result = await self._check_external_threat_intel(url)
                if ext_result:
                    result["source"] = "external"
                    result["score"] = max(result["score"], ext_result.get("score", 0))
                    if ext_result.get("malicious"):
                        result["is_malicious"] = True
                    result["reasons"].extend(ext_result.get("reasons", []))
            except Exception as e:
                logger.warning("External threat intel check failed: %s", str(e))

        result["is_malicious"] = result["score"] >= 0.7
        return result

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split("/")[0]
        except Exception:
            return url

    async def _check_external_threat_intel(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL against external threat intelligence API."""
        if not self._http_client:
            return None

        try:
            response = await self._http_client.post(
                self._settings.THREAT_INTEL_API_URL,
                json={"url": url},
                headers={
                    "Authorization": f"Bearer {self._settings.THREAT_INTEL_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            if response.is_success:
                data = response.json()
                return {
                    "score": data.get("score", 0.0),
                    "malicious": data.get("malicious", False),
                    "reasons": data.get("reasons", []),
                }
        except Exception as e:
            logger.debug("External threat intel error: %s", str(e))

        return None


@lru_cache
def get_url_protection_service() -> URLProtectionService:
    return URLProtectionService()
