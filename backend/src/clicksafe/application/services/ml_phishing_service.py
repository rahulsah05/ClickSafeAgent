"""Runtime phishing prediction. Training stays outside this service."""

import asyncio
import logging
from typing import Any, Protocol

from clicksafe.infrastructure.ml.phishing_classifier import (
    PhishingClassifier,
    unavailable_prediction,
)

logger = logging.getLogger(__name__)


class PhishingPredictor(Protocol):
    def predict(
        self,
        url: str,
        structured_features: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...


class MlPhishingService:
    def __init__(self, classifier: PhishingPredictor | None = None) -> None:
        self._classifier = classifier or PhishingClassifier()

    async def predict_url_risk(
        self,
        url: str,
        structured_features: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                self._classifier.predict,
                url,
                structured_features,
            )
        except Exception:
            logger.warning("ml.prediction_failed", extra={"event": "ml.prediction_failed"})
            result = unavailable_prediction("ML prediction failed")
            result["structured_feature_count"] = len(structured_features or {})
            return result
