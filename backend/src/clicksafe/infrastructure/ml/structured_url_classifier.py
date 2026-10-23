"""Runtime adapter for the structured URL model.

The scan calls this classifier. It measures the submitted URL with
structured_url_features and scores the saved logistic-regression bundle.
The result is evidence. It does not set the scan verdict. Class
probabilities are not calibrated.

The previous TF-IDF pipeline remains in phishing_classifier.py and is not
the active prediction call.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from clicksafe.infrastructure.ml.structured_url_features import (
    UrlFeatures,
    extract_url_features,
)
from clicksafe.infrastructure.ml.structured_url_model import (
    MODEL_VERSION,
    load_bundle,
    predict_feature_rows,
)

logger = logging.getLogger(__name__)

MODEL_TYPE = "logistic_regression"
_BUNDLES: dict[Path, dict[str, Any]] = {}
_LOAD_ERRORS: dict[Path, str] = {}


def default_structured_model_path() -> Path:
    packaged = Path(__file__).resolve().parent / "models" / "structured_url_model.joblib"
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[5] / "models" / "structured_url_model.joblib"


def unavailable_structured_prediction(error: str) -> dict[str, Any]:
    summary = "Local ML classifier was unavailable, so it contributed no evidence."
    return {
        "phishing_probability": None,
        "predicted_class": None,
        "predicted_label": None,
        "model_version": MODEL_VERSION,
        "model_type": MODEL_TYPE,
        "features_used": [],
        "model_available": False,
        "error": error,
        "summary": summary,
        "explanation": summary,
        "structured_feature_count": 0,
        "probabilities": None,
        "probabilities_calibrated": False,
        "extracted_features": {},
        "matched_brand": None,
        "matched_brand_token": None,
        "match_reason": None,
        "detected_transformations": [],
        "triggered_rules": [],
        "parse_error": None,
        "original_url": None,
        "brand_selection": "automatic",
        "feature_schema_version": None,
    }


class StructuredUrlClassifier:
    """Scores one URL with the saved structured bundle."""

    def __init__(self, model_path: Path | None = None) -> None:
        if model_path is None:
            model_path = default_structured_model_path()
        self._model_path = model_path
        self._bundle: dict[str, Any] | None = None
        self._load_error: str | None = None
        self._attempted = False

    def predict(
        self,
        url: str,
        structured_features: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del structured_features
        bundle = self._load()
        if bundle is None:
            return unavailable_structured_prediction(self._load_error or "ML model unavailable")
        try:
            text = url if isinstance(url, str) else ""
            extracted = extract_url_features(text)
            raw = predict_feature_rows(bundle, [extracted])[0]
            return _evidence(text, extracted, raw, bundle)
        except Exception:
            logger.warning("ml.prediction_failed", extra={"event": "ml.prediction_failed"})
            return unavailable_structured_prediction("ML prediction failed")

    def _load(self) -> dict[str, Any] | None:
        if self._attempted:
            return self._bundle

        self._attempted = True
        resolved = self._model_path.resolve()
        if resolved in _BUNDLES or resolved in _LOAD_ERRORS:
            self._bundle = _BUNDLES.get(resolved)
            self._load_error = _LOAD_ERRORS.get(resolved)
            return self._bundle

        if not self._model_path.is_file():
            self._load_error = "ML model unavailable"
            _LOAD_ERRORS[resolved] = self._load_error
            logger.warning("ml.model_unavailable", extra={"event": "ml.model_unavailable"})
            return None

        try:
            loaded = load_bundle(self._model_path)
        except Exception:
            self._bundle = None
            self._load_error = "ML model unavailable"
            _LOAD_ERRORS[resolved] = self._load_error
            logger.warning("ml.model_load_failed", extra={"event": "ml.model_load_failed"})
            return None

        self._bundle = dict(loaded)
        _BUNDLES[resolved] = self._bundle
        return self._bundle


def _count(features: dict[str, int | float | None], name: str) -> float | None:
    value = features.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _flag(features: dict[str, int | float | None], name: str) -> bool:
    value = _count(features, name)
    return value is not None and value >= 1


def triggered_rules(features: dict[str, int | float | None]) -> list[str]:
    """Describe measured signals. These sentences are not a verdict."""

    rules: list[str] = []
    substitutions = _count(features, "character_substitution_count")
    if substitutions is not None and substitutions >= 1:
        rules.append(f"Numeric character substitutions: {int(substitutions)}.")
    if _flag(features, "double_n_for_m_indicator"):
        rules.append("A doubled n collapses to m in the matched brand.")
    if _flag(features, "rn_for_m_indicator"):
        rules.append("An rn pair collapses to m in the matched brand.")
    if _flag(features, "character_insertion_indicator"):
        rules.append("The matched text is one insertion away from the brand.")
    if _flag(features, "character_deletion_indicator"):
        rules.append("The matched text is one deletion away from the brand.")
    if _flag(features, "character_transposition_indicator"):
        rules.append("The matched text is one adjacent transposition from the brand.")
    if _flag(features, "homoglyph_indicator"):
        rules.append("The hostname contains a confusable character.")
    if _flag(features, "mixed_script_indicator"):
        rules.append("The hostname mixes more than one script.")
    if _flag(features, "punycode_indicator"):
        rules.append("The hostname contains a Punycode label.")
    if _flag(features, "brand_in_subdomain"):
        rules.append("The brand token appears in a subdomain label.")
    if _flag(features, "misleading_domain_structure"):
        rules.append("The brand token sits in a misleading host label.")
    keywords = _count(features, "suspicious_keyword_count")
    if keywords is not None and keywords >= 1:
        rules.append(f"Suspicious keyword tokens: {int(keywords)}.")
    subdomains = _count(features, "subdomain_count")
    if subdomains is not None and subdomains >= 4:
        rules.append(f"Subdomain labels: {int(subdomains)}.")
    repeats = _count(features, "repeated_character_count")
    if repeats is not None and repeats >= 4:
        rules.append(f"Repeated adjacent hostname characters: {int(repeats)}.")
    return rules


def _tags(transformation_types: str | None) -> list[str]:
    if not transformation_types or transformation_types == "none":
        return []
    return [tag for tag in transformation_types.split(";") if tag and tag != "none"]


def _explanation(label: str, brand: str | None, probability: float | None) -> str:
    brand_text = brand if brand else "none"
    score = "unavailable" if probability is None else f"{probability:.4f}"
    return (
        f"Structured URL model predicted {label}. "
        f"Matched brand: {brand_text}. "
        f"Uncalibrated malicious-class probability: {score}. "
        "This is one evidence source and does not set the scan verdict."
    )


def _probabilities(raw: object) -> dict[str, float] | None:
    if not isinstance(raw, dict):
        return None
    return {str(key): round(float(value), 6) for key, value in raw.items()}


def _json_features(
    features: dict[str, int | float | None],
) -> dict[str, int | float | None]:
    cleaned: dict[str, int | float | None] = {}
    for name, value in features.items():
        if isinstance(value, float):
            cleaned[name] = round(value, 6)
        else:
            cleaned[name] = value
    return cleaned


def _evidence(
    url: str,
    extracted: UrlFeatures,
    raw: dict[str, object],
    bundle: dict[str, Any],
) -> dict[str, Any]:
    features = _json_features(dict(extracted.features))
    probabilities = _probabilities(raw.get("probabilities"))
    malicious = None if probabilities is None else probabilities.get("malicious")
    label = str(raw["predicted_label"])
    tags = _tags(extracted.transformation_types)
    present = sum(value is not None for value in features.values())
    summary = _explanation(label, extracted.brand_name, malicious)
    return {
        "phishing_probability": malicious,
        "predicted_class": label,
        "predicted_label": label,
        "model_version": str(bundle.get("model_version") or MODEL_VERSION),
        "model_type": str(bundle.get("model_type") or MODEL_TYPE),
        "features_used": tags[:24],
        "model_available": True,
        "error": None,
        "summary": summary,
        "explanation": summary,
        "structured_feature_count": present,
        "probabilities": probabilities,
        "probabilities_calibrated": False,
        "extracted_features": features,
        "matched_brand": extracted.brand_name,
        "matched_brand_token": extracted.brand_token,
        "match_reason": extracted.match_reason,
        "detected_transformations": tags,
        "triggered_rules": triggered_rules(features),
        "parse_error": extracted.parse_error,
        "original_url": extracted.original_url or url,
        "brand_selection": str(bundle.get("brand_selection") or "automatic"),
        "feature_schema_version": bundle.get("feature_schema_version"),
    }
