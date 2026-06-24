"""Threat scoring and verdict engine.

Aggregates results from NLP, Vision, URL, and CDR engines.
Computes a weighted threat score and produces a final verdict.
"""

import logging
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from shared.config.settings import get_settings
from shared.database.session import async_session_factory

logger = logging.getLogger(__name__)

# Verdict thresholds
VERDICT_THRESHOLDS = [
    (0.0, "ALLOW"),
    (0.4, "SUSPICIOUS"),
    (0.7, "QUARANTINE"),
    (0.9, "BLOCK"),
]

# Default weights for each engine
DEFAULT_WEIGHTS = {
    "nlp": 0.35,
    "vision": 0.20,
    "url": 0.25,
    "cdr": 0.20,
}


class ThreatScorer:
    """Aggregate multi-engine results into a final threat verdict."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._weights = DEFAULT_WEIGHTS

    def calculate_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate final threat score and verdict from all engine results."""
        nlp_result = results.get("nlp", {})
        vision_result = results.get("vision", {})
        url_result = results.get("url", {})
        cdr_result = results.get("cdr", {})

        # Extract individual scores (0.0-1.0)
        nlp_score = self._extract_score(nlp_result, "score", "threat_score")
        vision_score = self._extract_score(vision_result, "image_phishing_score", "score")
        url_score = self._extract_score(url_result, "max_score", "score")
        cdr_score = self._extract_cdr_score(cdr_result)

        # Weighted aggregate
        weighted_sum = (
            nlp_score * self._weights["nlp"]
            + vision_score * self._weights["vision"]
            + url_score * self._weights["url"]
            + cdr_score * self._weights["cdr"]
        )

        # Apply boosts
        boost = self._calculate_boost(nlp_result, vision_result, url_result, cdr_result)
        final_score = min(weighted_sum + boost, 1.0)

        # Determine verdict
        verdict = self._determine_verdict(final_score)

        # Determine threat type
        threat_type = self._determine_threat_type(nlp_result, vision_result, url_result)

        # Build detailed components
        components = {
            "nlp": {"score": nlp_score, "label": nlp_result.get("label", "unknown")},
            "vision": {"score": vision_score, "label": vision_result.get("vision_label", "none")},
            "url": {"score": url_score, "malicious_urls": url_result.get("has_malicious", False)},
            "cdr": {"score": cdr_score, "issues": len(cdr_result.get("issues_found", []))},
        }

        return {
            "threat_score": round(final_score, 4),
            "verdict": verdict,
            "threat_type": threat_type,
            "components": components,
            "boost_applied": round(boost, 4),
        }

    def _extract_score(self, result: Dict[str, Any], *keys: str) -> float:
        """Extract score from result dict using priority keys."""
        for key in keys:
            value = result.get(key)
            if value is not None:
                try:
                    return min(float(value), 1.0)
                except (ValueError, TypeError):
                    continue
        return 0.0

    def _extract_cdr_score(self, cdr_result: Dict[str, Any]) -> float:
        """Convert CDR result to a 0-1 threat score."""
        issues = cdr_result.get("issues_found", []) or cdr_result.get("issues_removed", [])
        if not issues:
            return 0.0
        # More issues = higher threat
        return min(len(issues) * 0.25, 1.0)

    def _calculate_boost(
        self,
        nlp: Dict[str, Any],
        vision: Dict[str, Any],
        url: Dict[str, Any],
        cdr: Dict[str, Any],
    ) -> float:
        """Calculate score boost based on combined signals."""
        boost = 0.0

        # Multiple high scores boost each other
        high_scores = 0
        if self._extract_score(nlp, "score", "threat_score") >= 0.7:
            high_scores += 1
        if self._extract_score(vision, "image_phishing_score", "score") >= 0.7:
            high_scores += 1
        if self._extract_score(url, "max_score", "score") >= 0.7:
            high_scores += 1
        if self._extract_cdr_score(cdr) >= 0.7:
            high_scores += 1

        if high_scores >= 2:
            boost += 0.1
        if high_scores >= 3:
            boost += 0.1

        # QR + malicious URL is high risk
        if vision.get("has_qr") and url.get("has_malicious"):
            boost += 0.15

        # BEC detection + any other signal
        if nlp.get("label") == "BEC" and high_scores >= 1:
            boost += 0.1

        return min(boost, 0.3)

    def _determine_verdict(self, score: float) -> str:
        """Map score to verdict."""
        for threshold, verdict in reversed(VERDICT_THRESHOLDS):
            if score >= threshold:
                return verdict
        return "ALLOW"

    def _determine_threat_type(
        self,
        nlp: Dict[str, Any],
        vision: Dict[str, Any],
        url: Dict[str, Any],
    ) -> str:
        """Determine the primary threat type based on highest contributing engine."""
        nlp_label = nlp.get("label", "")
        if nlp_label in ("BEC", "PHISHING", "FINANCIAL_FRAUD", "CREDENTIAL_THEFT", "SOCIAL_ENGINEERING"):
            return nlp_label

        if vision.get("has_qr"):
            return "QUISHING"

        if url.get("has_malicious"):
            return "MALICIOUS_URL"

        return "UNKNOWN"


@lru_cache
def get_threat_scorer() -> ThreatScorer:
    return ThreatScorer()
