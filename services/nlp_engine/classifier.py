"""NLP threat classification engine using DeBERTa-v3."""

import logging
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional

import numpy as np

from shared.config.settings import get_settings

logger = logging.getLogger(__name__)

THREAT_CATEGORIES = {
    "SAFE": 0.0,
    "PHISHING": 0.7,
    "BEC": 0.85,
    "SOCIAL_ENGINEERING": 0.75,
    "FINANCIAL_FRAUD": 0.9,
    "CREDENTIAL_THEFT": 0.8,
}


class NLPClassifier:
    """DeBERTa-v3 based text classifier for email threat detection."""

    def __init__(self) -> None:
        self._model = None
        self._tokenizer = None
        self._session = None
        self._settings = get_settings()
        self._loaded = False
        self._labels = [
            "SAFE",
            "PHISHING",
            "BEC",
            "SOCIAL_ENGINEERING",
            "FINANCIAL_FRAUD",
            "CREDENTIAL_THEFT",
        ]

    def load_model(self) -> None:
        """Load DeBERTa-v3 model. Falls back to ONNX if available."""
        try:
            self._load_transformers()
        except Exception as e:
            logger.warning("Failed to load Transformers model: %s, trying ONNX", e)
            try:
                self._load_onnx()
            except Exception as e2:
                logger.warning("Failed to load ONNX model: %s, using heuristic fallback", e2)
                self._loaded = False
                return
        self._loaded = True
        logger.info("NLP model loaded successfully")

    def _load_transformers(self) -> None:
        """Load model via HuggingFace Transformers."""
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        model_name = self._settings.NLP_MODEL_NAME or "microsoft/deberta-v3-small"
        logger.info("Loading NLP model: %s", model_name)

        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            return_dict=True,
        )

        import torch
        if torch.cuda.is_available():
            self._model = self._model.to("cuda")
            logger.info("NLP model moved to GPU")

        self._model.eval()

    def _load_onnx(self) -> None:
        """Load model via ONNX Runtime for faster inference."""
        import onnxruntime as ort

        model_path = self._settings.NLP_ONNX_PATH or "/models/nlp/model.onnx"
        logger.info("Loading ONNX model from: %s", model_path)

        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
        self._session = ort.InferenceSession(model_path, providers=providers)

        from transformers import AutoTokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(
            self._settings.NLP_MODEL_NAME or "microsoft/deberta-v3-small",
        )

    @lru_cache(maxsize=10000)
    def _cached_tokenize(self, text: str) -> Any:
        """Tokenize with caching for repeated text patterns."""
        if self._tokenizer is None:
            return None
        return self._tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=512,
            return_tensors="pt",
            return_attention_mask=True,
        )

    def predict(self, text: str) -> Dict[str, Any]:
        """Run inference on email body text and return classification."""
        if not text or not text.strip():
            return {
                "label": "SAFE",
                "score": 1.0,
                "confidence": 1.0,
                "threat_score": 0.0,
            }

        start_time = time.time()

        if not self._loaded:
            result = self._heuristic_classify(text)
        elif self._session:
            result = self._predict_onnx(text)
        else:
            result = self._predict_transformers(text)

        elapsed = int((time.time() - start_time) * 1000)
        result["analysis_duration_ms"] = elapsed
        result["threat_score"] = THREAT_CATEGORIES.get(result["label"], 0.5)

        logger.debug(
            "NLP inference: label=%s score=%.4f time=%dms",
            result["label"],
            result.get("score", 0),
            elapsed,
        )

        return result

    def _predict_transformers(self, text: str) -> Dict[str, Any]:
        """Run inference using Transformers pipeline."""
        import torch

        inputs = self._cached_tokenize(text)
        if inputs is None:
            return self._heuristic_classify(text)

        device = next(self._model.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self._model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)
            scores = probabilities[0].cpu().numpy()

        predicted_idx = int(np.argmax(scores))
        return {
            "label": self._labels[predicted_idx] if predicted_idx < len(self._labels) else "SAFE",
            "score": float(scores[predicted_idx]),
            "confidence": float(scores[predicted_idx]),
            "all_scores": {
                label: float(score)
                for label, score in zip(self._labels, scores)
            },
        }

    def _predict_onnx(self, text: str) -> Dict[str, Any]:
        """Run inference using ONNX Runtime."""
        import onnxruntime as ort

        inputs = self._cached_tokenize(text)
        if inputs is None:
            return self._heuristic_classify(text)

        ort_inputs = {
            self._session.get_inputs()[0].name: inputs["input_ids"].numpy(),
            self._session.get_inputs()[1].name: inputs["attention_mask"].numpy(),
        }
        ort_outputs = self._session.run(None, ort_inputs)
        scores = ort_outputs[0][0]
        scores = np.exp(scores) / np.sum(np.exp(scores))

        predicted_idx = int(np.argmax(scores))
        return {
            "label": self._labels[predicted_idx] if predicted_idx < len(self._labels) else "SAFE",
            "score": float(scores[predicted_idx]),
            "confidence": float(scores[predicted_idx]),
            "all_scores": {
                label: float(score)
                for label, score in zip(self._labels, scores)
            },
        }

    def _heuristic_classify(self, text: str) -> Dict[str, Any]:
        """Fallback heuristic classifier when model is unavailable."""
        text_lower = text.lower()
        scores = {}

        # BEC indicators
        bec_score = 0.0
        bec_patterns = ["urgent", "wire transfer", "payment", "invoice", "ceo", "president",
                        "confidential", "request", "action required", "immediately"]
        bec_matches = sum(1 for p in bec_patterns if p in text_lower)
        bec_score = min(bec_matches / len(bec_patterns), 1.0)
        scores["BEC"] = bec_score

        # Phishing indicators
        phish_score = 0.0
        phish_patterns = ["verify", "account", "password", "login", "click here",
                          "suspended", "security", "bank", "credit card", "social security"]
        phish_matches = sum(1 for p in phish_patterns if p in text_lower)
        phish_score = min(phish_matches / len(phish_patterns), 1.0)
        scores["PHISHING"] = phish_score

        # Social Engineering
        se_score = 0.0
        se_patterns = ["help", "emergency", "please", "kindly", "assistance",
                       "personal", "friend", "family", "donation", "charity"]
        se_matches = sum(1 for p in se_patterns if p in text_lower)
        se_score = min(se_matches / len(se_patterns), 1.0)
        scores["SOCIAL_ENGINEERING"] = se_score

        # Financial Fraud
        ff_score = 0.0
        ff_patterns = ["account number", "routing", "iban", "swift", "deposit",
                       "withdraw", "transfer", "million", "inheritance", "lottery"]
        ff_matches = sum(1 for p in ff_patterns if p in text_lower)
        ff_score = min(ff_matches / len(ff_patterns), 1.0)
        scores["FINANCIAL_FRAUD"] = ff_score

        # Credential Theft
        ct_score = 0.0
        ct_patterns = ["username", "password", "credential", "login details",
                       "sign in", "verify account", "2fa", "otp", "one-time"]
        ct_matches = sum(1 for p in ct_patterns if p in text_lower)
        ct_score = min(ct_matches / len(ct_patterns), 1.0)
        scores["CREDENTIAL_THEFT"] = ct_score

        # Overall SAFE if below threshold
        scores["SAFE"] = 1.0 - max(bec_score, phish_score, se_score, ff_score, ct_score)

        best_label = max(scores, key=scores.get)
        return {
            "label": best_label,
            "score": scores[best_label],
            "confidence": scores[best_label],
            "all_scores": scores,
            "is_fallback": True,
        }


@lru_cache
def get_nlp_classifier() -> NLPClassifier:
    classifier = NLPClassifier()
    classifier.load_model()
    return classifier
