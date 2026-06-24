from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.nlp_engine.classifier import get_nlp_classifier

router = APIRouter(prefix="/api/v1", tags=["nlp"])


class PredictRequest(BaseModel):
    message_id: str
    body: str


class PredictResponse(BaseModel):
    message_id: str
    label: str
    score: float
    confidence: float
    threat_score: float
    analysis_duration_ms: int
    all_scores: dict


@router.post(
    "/predict",
    response_model=PredictResponse,
    summary="Classify email text for threats",
    description="Run NLP inference on email body text to detect phishing, BEC, etc.",
)
async def predict(request: PredictRequest):
    if not request.body or not request.body.strip():
        raise HTTPException(status_code=400, detail="Email body is empty")

    classifier = get_nlp_classifier()
    result = classifier.predict(request.body)

    return PredictResponse(
        message_id=request.message_id,
        label=result["label"],
        score=result.get("score", 0.0),
        confidence=result.get("confidence", 0.0),
        threat_score=result.get("threat_score", 0.0),
        analysis_duration_ms=result.get("analysis_duration_ms", 0),
        all_scores=result.get("all_scores", {}),
    )
