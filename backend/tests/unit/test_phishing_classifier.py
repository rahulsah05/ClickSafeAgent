from pathlib import Path

import pytest

from clicksafe.application.services.ml_phishing_service import MlPhishingService
from clicksafe.infrastructure.ml.phishing_classifier import (
    PhishingClassifier,
    UrlTextModelAdapter,
)

LEGITIMATE_URL = "https://google.com/123"
SUSPICIOUS_URL = "https://login-google-456.xyz/security"
PHISHING_URL = "http://login-google-456.xyz/security"


def test_loads_saved_model_and_reports_its_contract() -> None:
    result = PhishingClassifier().predict(LEGITIMATE_URL)

    assert result["model_available"] is True
    assert result["error"] is None
    assert result["model_type"] == "LogisticRegression"
    assert result["model_version"] == "1.0"
    assert result["predicted_class"] == "legitimate"
    assert result["phishing_probability"] < 0.05


def test_legitimate_url_stays_low_probability() -> None:
    result = PhishingClassifier().predict("https://wikipedia.org/100")

    assert result["predicted_class"] == "legitimate"
    assert result["phishing_probability"] < 0.05
    assert result["summary"] == (
        "Local ML classifier did not estimate a high phishing probability."
    )


def test_suspicious_url_is_elevated_but_less_certain_than_the_phishing_pattern() -> None:
    classifier = PhishingClassifier()
    suspicious = classifier.predict(SUSPICIOUS_URL)
    phishing = classifier.predict(PHISHING_URL)

    assert suspicious["predicted_class"] == "phishing"
    assert 0.5 < suspicious["phishing_probability"] < 0.95
    assert phishing["phishing_probability"] > suspicious["phishing_probability"]


def test_phishing_url_returns_high_probability_as_evidence() -> None:
    result = PhishingClassifier().predict(PHISHING_URL)

    assert result["predicted_class"] == "phishing"
    assert result["phishing_probability"] > 0.9
    assert result["summary"] == "Local ML classifier estimated a high phishing probability."
    assert result["model_available"] is True


def test_invalid_url_returns_a_controlled_prediction() -> None:
    result = PhishingClassifier().predict("")

    assert result["model_available"] is True
    assert result["error"] is None
    assert result["predicted_class"] in {"legitimate", "phishing"}
    assert 0.0 <= result["phishing_probability"] <= 1.0


def test_feature_extraction_uses_url_text_tokens() -> None:
    text, structured_count = UrlTextModelAdapter().to_model_text(
        LEGITIMATE_URL,
        {"url_length": 22, "has_ip_address": False},
    )
    result = PhishingClassifier().predict(
        LEGITIMATE_URL,
        {"url_length": 22, "has_ip_address": False},
    )

    assert text == LEGITIMATE_URL
    assert structured_count == 2
    assert result["structured_feature_count"] == 2
    assert "google.com" in result["features_used"]
    assert "url_length" not in result["features_used"]


def test_missing_model_is_unavailable(tmp_path: Path) -> None:
    result = PhishingClassifier(tmp_path / "missing.joblib").predict(LEGITIMATE_URL)

    assert result["model_available"] is False
    assert result["error"] == "ML model unavailable"
    assert result["phishing_probability"] is None
    assert result["predicted_class"] is None
    assert result["features_used"] == []


def test_corrupt_model_is_unavailable(tmp_path: Path) -> None:
    model_path = tmp_path / "model.joblib"
    model_path.write_bytes(b"not-a-model")

    result = PhishingClassifier(model_path).predict(LEGITIMATE_URL)

    assert result["model_available"] is False
    assert result["error"] == "ML model unavailable"


class ExplodingPredictor:
    def predict(
        self,
        url: str,
        structured_features: dict[str, object] | None = None,
    ) -> dict[str, object]:
        _ = url, structured_features
        raise RuntimeError("classifier crashed")


async def test_prediction_failure_is_isolated() -> None:
    result = await MlPhishingService(ExplodingPredictor()).predict_url_risk(PHISHING_URL)

    assert result["model_available"] is False
    assert result["error"] == "ML prediction failed"


def test_saved_model_does_not_receive_structured_features() -> None:
    adapter = UrlTextModelAdapter()
    without_features, _ = adapter.to_model_text(PHISHING_URL, None)
    with_features, count = adapter.to_model_text(
        PHISHING_URL,
        {"suspicious_keywords": ["login"], "brand_domain_mismatch": True},
    )

    assert with_features == without_features == PHISHING_URL
    assert count == 2


@pytest.mark.parametrize(
    "url",
    [LEGITIMATE_URL, SUSPICIOUS_URL, PHISHING_URL, "not a url"],
)
def test_prediction_shape(url: str) -> None:
    result = PhishingClassifier().predict(url)

    assert set(result) >= {
        "phishing_probability",
        "predicted_class",
        "model_version",
        "model_type",
        "features_used",
        "model_available",
    }
