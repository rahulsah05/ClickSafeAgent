"""Live structured URL classifier used by the scan."""

from __future__ import annotations

import hashlib
from pathlib import Path

from clicksafe.application.services.ml_phishing_service import MlPhishingService
from clicksafe.infrastructure.ml.structured_url_classifier import (
    StructuredUrlClassifier,
    default_structured_model_path,
)
from clicksafe.infrastructure.ml.structured_url_features import METADATA_COLUMNS

ROOT = Path(__file__).resolve().parents[3]
PACKAGED = (
    ROOT
    / "backend"
    / "src"
    / "clicksafe"
    / "infrastructure"
    / "ml"
    / "models"
    / "structured_url_model.joblib"
)
TRAINED = ROOT / "models" / "structured_url_model.joblib"
LIVE = (
    ROOT
    / "backend"
    / "src"
    / "clicksafe"
    / "infrastructure"
    / "ml"
    / "models"
    / "model.joblib"
)
EXPECTED_SHA = "a8f54ade45caeb0d92cbb3f338be7b9ca23b4a7ea58bae3b26eabeb7808c1be3"
LABELS = {"legitimate", "suspicious", "malicious"}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_packaged_bundle_matches_the_training_artifact() -> None:
    assert default_structured_model_path().resolve() == PACKAGED.resolve()
    assert _sha(PACKAGED) == _sha(TRAINED) == EXPECTED_SHA
    assert LIVE.is_file()
    assert LIVE.stat().st_size == 3644548


def test_exact_brand_host_stays_legitimate() -> None:
    result = StructuredUrlClassifier().predict("https://google.com/123")

    assert result["model_available"] is True
    assert result["error"] is None
    assert result["model_type"] == "logistic_regression"
    assert result["model_version"] == "2.0.0"
    assert result["predicted_label"] == "legitimate"
    assert result["predicted_class"] == "legitimate"
    assert result["phishing_probability"] < 0.05
    assert result["probabilities_calibrated"] is False
    assert result["matched_brand"] == "Google"
    assert result["match_reason"] == "exact"
    assert result["brand_selection"] == "automatic"
    assert "does not set the scan verdict" in result["explanation"]
    assert set(METADATA_COLUMNS).isdisjoint(result["extracted_features"])


def test_keywords_alone_stay_legitimate() -> None:
    result = StructuredUrlClassifier().predict(
        "https://example.com/login/account/secure/payment",
    )

    assert result["predicted_label"] == "legitimate"
    assert result["phishing_probability"] < 0.05
    assert result["matched_brand"] is None


def test_lookalike_with_a_lure_is_malicious_evidence() -> None:
    exact = StructuredUrlClassifier().predict("https://paypal.test/login")
    lookalike = StructuredUrlClassifier().predict("https://paypa1.test/login")

    assert exact["predicted_label"] == "legitimate"
    assert exact["matched_brand"] == "PayPal"
    assert lookalike["predicted_label"] == "malicious"
    assert lookalike["matched_brand"] == "PayPal"
    assert lookalike["match_reason"] == "digit_lookalike"
    assert lookalike["phishing_probability"] > 0.9
    assert "numeric_substitution" in lookalike["detected_transformations"]
    assert any("substitution" in rule for rule in lookalike["triggered_rules"])


def test_misleading_brand_host_is_malicious_for_either_scheme() -> None:
    https_result = StructuredUrlClassifier().predict("https://login-google-456.xyz/security")
    http_result = StructuredUrlClassifier().predict("http://login-google-456.xyz/security")

    assert https_result["predicted_label"] == "malicious"
    assert http_result["predicted_label"] == "malicious"
    assert https_result["phishing_probability"] > 0.9
    assert http_result["phishing_probability"] > 0.9


def test_invalid_urls_return_a_controlled_prediction() -> None:
    empty = StructuredUrlClassifier().predict("")
    broken = StructuredUrlClassifier().predict("not a url")

    assert empty["model_available"] is True
    assert empty["parse_error"] == "empty"
    assert empty["predicted_label"] in LABELS
    assert broken["parse_error"] == "unusable_url"
    assert broken["predicted_label"] in LABELS
    assert 0.0 <= broken["phishing_probability"] <= 1.0


def test_supplied_pre_scan_features_are_not_model_inputs() -> None:
    classifier = StructuredUrlClassifier()
    url = "https://google.com/123"
    alone = classifier.predict(url)
    offered = classifier.predict(url, {"label": "malicious", "url_length": 1})

    assert offered["predicted_label"] == alone["predicted_label"]
    assert offered["extracted_features"] == alone["extracted_features"]
    assert "label" not in offered["extracted_features"]


def test_missing_model_is_unavailable(tmp_path: Path) -> None:
    missing = tmp_path / "missing.joblib"
    result = StructuredUrlClassifier(missing).predict("https://google.com/123")

    assert result["model_available"] is False
    assert result["error"] == "ML model unavailable"
    assert result["predicted_label"] is None
    assert result["phishing_probability"] is None


def test_corrupt_model_is_unavailable(tmp_path: Path) -> None:
    model_path = tmp_path / "model.joblib"
    model_path.write_bytes(b"not-a-model")

    result = StructuredUrlClassifier(model_path).predict("https://google.com/123")

    assert result["model_available"] is False
    assert result["error"] == "ML model unavailable"


async def test_service_uses_the_structured_model() -> None:
    result = await MlPhishingService().predict_url_risk("https://wikipedia.org/100")

    assert result["model_type"] == "logistic_regression"
    assert result["predicted_label"] == "legitimate"
    assert result["matched_brand"] == "Wikipedia"
    assert result["phishing_probability"] < 0.05
