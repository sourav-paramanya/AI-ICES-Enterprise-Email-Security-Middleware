"""Threat scoring API endpoints."""

from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from services.threat_orchestrator.scorer import get_threat_scorer

router = APIRouter(prefix="/api/v1", tags=["scoring"])


class ScoreRequest(BaseModel):
    session_id: str
    message_id: Optional[str] = None
    nlp_result: Optional[Dict[str, Any]] = None
    vision_result: Optional[Dict[str, Any]] = None
    url_result: Optional[Dict[str, Any]] = None
    cdr_result: Optional[Dict[str, Any]] = None


class ComponentDetail(BaseModel):
    score: float
    label: str


class ScoreResponse(BaseModel):
    session_id: str
    message_id: Optional[str] = None
    threat_score: float
    verdict: str
    threat_type: str
    components: Dict[str, ComponentDetail]
    boost_applied: float


@router.post(
    "/score",
    response_model=ScoreResponse,
    summary="Calculate threat score from engine results",
)
async def calculate_score(request: ScoreRequest):
    scorer = get_threat_scorer()

    results = {}
    if request.nlp_result:
        results["nlp"] = request.nlp_result
    if request.vision_result:
        results["vision"] = request.vision_result
    if request.url_result:
        results["url"] = request.url_result
    if request.cdr_result:
        results["cdr"] = request.cdr_result

    score_result = scorer.calculate_score(results)

    return ScoreResponse(
        session_id=request.session_id,
        message_id=request.message_id,
        threat_score=score_result["threat_score"],
        verdict=score_result["verdict"],
        threat_type=score_result["threat_type"],
        components={
            key: ComponentDetail(**val)
            for key, val in score_result["components"].items()
        },
        boost_applied=score_result["boost_applied"],
    )
