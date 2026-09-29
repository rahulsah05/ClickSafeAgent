"""Local loader for the existing phishing URL classifier.

The saved pipeline is TF-IDF plus logistic regression, trained on raw URL text.
Structured pre-scan features are not model inputs.
"""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
_LOADED_PIPELINES: dict[Path, Any] = {}
_LOAD_ERRORS: dict[Path, str] = {}

MODEL_VERSION = "1.0"
MODEL_TYPE = "LogisticRegression"
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "model.joblib"
PHISHING_LABEL = "bad"
LABELS = {PHISHING_LABEL: "phishing", "good": "legitimate"}
MAX_LISTED_FEATURES = 24


class UrlTextModelAdapter:
    """Keeps the saved model on the URL string it was trained with."""

    def to_model_text(
        self,
        url: str,
        structured_features: dict[str, Any] | None = None,
    ) -> tuple[str, int]:
        feature_count = len(structured_features) if structured_features else 0
        text = "" if url is None else str(url).strip()
        return text, feature_count


def unavailable_prediction(error: str) -> dict[str, Any]:
    return {
        "phishing_probability": None,
        "predicted_class": None,
        "model_version": MODEL_VERSION,
        "model_type": MODEL_TYPE,
        "features_used": [],
        "model_available": False,
        "error": error,
        "summary": "Local ML classifier was unavailable, so it contributed no evidence.",
        "structured_feature_count": 0,
    }


class PhishingClassifier:
    def __init__(self, model_path: Path | None = None) -> None:
        self._model_path = model_path if model_path is not None else DEFAULT_MODEL_PATH
        self._adapter = UrlTextModelAdapter()
        self._pipeline: Any = None
        self._load_error: str | None = None
        self._attempted = False

    def predict(
        self,
        url: str,
        structured_features: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        pipeline = self._load()
        if pipeline is None:
            result = unavailable_prediction(self._load_error or "ML model unavailable")
            result["structured_feature_count"] = len(structured_features or {})
            return result

        try:
            text, structured_feature_count = self._adapter.to_model_text(url, structured_features)
            raw_label = str(pipeline.predict([text])[0])
            probabilities = pipeline.predict_proba([text])[0]
            classes = [str(label) for label in pipeline.named_steps["model"].classes_]
            phishing_probability = float(probabilities[classes.index(PHISHING_LABEL)])
            predicted_class = LABELS.get(raw_label, raw_label)
            return {
                "phishing_probability": round(phishing_probability, 6),
                "predicted_class": predicted_class,
                "model_version": MODEL_VERSION,
                "model_type": MODEL_TYPE,
                "features_used": self._features_used(pipeline, text),
                "model_available": True,
                "error": None,
                "summary": self._summary(predicted_class, phishing_probability),
                "structured_feature_count": structured_feature_count,
            }
        except Exception:
            logger.warning("ml.prediction_failed", extra={"event": "ml.prediction_failed"})
            result = unavailable_prediction("ML prediction failed")
            result["structured_feature_count"] = len(structured_features or {})
            return result

    def _load(self) -> Any:
        if self._attempted:
            return self._pipeline

        self._attempted = True
        resolved_path = self._model_path.resolve()
        if resolved_path in _LOADED_PIPELINES or resolved_path in _LOAD_ERRORS:
            self._pipeline = _LOADED_PIPELINES.get(resolved_path)
            self._load_error = _LOAD_ERRORS.get(resolved_path)
            return self._pipeline

        if not self._model_path.is_file():
            self._load_error = "ML model unavailable"
            _LOAD_ERRORS[resolved_path] = self._load_error
            logger.warning("ml.model_unavailable", extra={"event": "ml.model_unavailable"})
            return None

        try:
            import joblib  # type: ignore[import-untyped]

            self._pipeline = joblib.load(self._model_path)
            _LOADED_PIPELINES[resolved_path] = self._pipeline
        except Exception:
            self._pipeline = None
            self._load_error = "ML model unavailable"
            _LOAD_ERRORS[resolved_path] = self._load_error
            logger.warning("ml.model_load_failed", extra={"event": "ml.model_load_failed"})
        return self._pipeline

    def _features_used(self, pipeline: Any, text: str) -> list[str]:
        vectorizer = pipeline.named_steps["vectorizer"]
        vocabulary = vectorizer.vocabulary_
        used: list[str] = []
        for token in vectorizer.build_analyzer()(text):
            if token in vocabulary and token not in used:
                used.append(str(token))
            if len(used) >= MAX_LISTED_FEATURES:
                break
        return used

    def _summary(self, predicted_class: str, phishing_probability: float) -> str:
        if predicted_class == "phishing" and phishing_probability >= 0.7:
            return "Local ML classifier estimated a high phishing probability."
        if predicted_class == "phishing":
            return "Local ML classifier estimated an elevated phishing probability."
        return "Local ML classifier did not estimate a high phishing probability."
