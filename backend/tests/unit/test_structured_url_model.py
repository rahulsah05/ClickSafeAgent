"""Selection policy, rule baseline, and the saved structured model bundle."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from clicksafe.infrastructure.ml.structured_url_features import (
    METADATA_COLUMNS,
    MODEL_FEATURE_COLUMNS,
)
from clicksafe.infrastructure.ml.structured_url_model import (
    assign_grouped_splits,
    load_bundle,
    matrix_from_features,
    predict_feature_rows,
    predict_url,
    rule_label,
    select_model,
)
from clicksafe.infrastructure.ml.structured_url_features import extract_url_features

ROOT = Path(__file__).resolve().parents[3]
BUNDLE_PATH = ROOT / "models" / "structured_url_model.joblib"
METRICS_PATH = ROOT / "models" / "structured_url_model.metrics.json"
LIVE_MODEL = (
    ROOT
    / "backend"
    / "src"
    / "clicksafe"
    / "infrastructure"
    / "ml"
    / "models"
    / "model.joblib"
)


def _vector(**overrides: float) -> np.ndarray:
    values = np.zeros(len(MODEL_FEATURE_COLUMNS), dtype=float)
    values[MODEL_FEATURE_COLUMNS.index("edit_distance")] = np.nan
    values[MODEL_FEATURE_COLUMNS.index("brand_similarity_score")] = np.nan
    for name in (
        "character_substitution_count",
        "zero_for_o_count",
        "one_for_l_or_i_count",
        "three_for_e_count",
        "five_for_s_count",
        "double_n_for_m_indicator",
        "rn_for_m_indicator",
        "character_insertion_indicator",
        "character_deletion_indicator",
        "character_transposition_indicator",
        "brand_in_subdomain",
    ):
        values[MODEL_FEATURE_COLUMNS.index(name)] = np.nan
    for name, value in overrides.items():
        values[MODEL_FEATURE_COLUMNS.index(name)] = value
    return values


def _scores(f1: float, rate: float) -> dict[str, float]:
    return {"macro_f1": f1, "legitimate_as_malicious_rate": rate}


def test_selection_prefers_a_clearly_better_eligible_model() -> None:
    chosen, _reason = select_model(
        {
            "rule_baseline": _scores(0.90, 0.0),
            "logistic_regression": _scores(0.91, 0.0),
            "random_forest": _scores(0.96, 0.0),
            "hist_gradient_boosting": _scores(0.97, 0.01),
        }
    )

    assert chosen == "random_forest"


def test_selection_breaks_close_scores_toward_the_rule() -> None:
    chosen, _reason = select_model(
        {
            "rule_baseline": _scores(0.95, 0.0),
            "logistic_regression": _scores(0.955, 0.0),
            "random_forest": _scores(0.958, 0.0),
            "hist_gradient_boosting": _scores(0.959, 0.0),
        }
    )

    assert chosen == "rule_baseline"


def test_selection_rejects_a_higher_score_with_more_false_positives() -> None:
    chosen, _reason = select_model(
        {
            "rule_baseline": _scores(0.80, 0.0),
            "logistic_regression": _scores(0.93, 0.02),
            "random_forest": _scores(0.99, 0.02),
            "hist_gradient_boosting": _scores(0.98, 0.03),
        }
    )

    assert chosen == "rule_baseline"


def test_rule_treats_keywords_as_insufficient_on_their_own() -> None:
    legitimate = _vector(
        edit_distance=0,
        brand_similarity_score=1,
        character_substitution_count=0,
        suspicious_keyword_count=3,
        misleading_domain_structure=0,
        brand_in_subdomain=0,
    )
    keyword_only = _vector(suspicious_keyword_count=3, misleading_domain_structure=0)
    structure_only = _vector(suspicious_keyword_count=0, misleading_domain_structure=1)
    keyword_structure = _vector(suspicious_keyword_count=2, misleading_domain_structure=1)
    one_digit = _vector(character_substitution_count=1, edit_distance=1, suspicious_keyword_count=0)
    strong = _vector(character_substitution_count=2, suspicious_keyword_count=1, edit_distance=2)
    homoglyph = _vector(homoglyph_indicator=1, suspicious_keyword_count=0, edit_distance=1)
    homoglyph_lure = _vector(homoglyph_indicator=1, suspicious_keyword_count=1, edit_distance=1)
    deep_generic = _vector(subdomain_count=4, suspicious_keyword_count=0)

    assert rule_label(legitimate) == "legitimate"
    assert rule_label(keyword_only) == "legitimate"
    assert rule_label(structure_only) == "suspicious"
    assert rule_label(keyword_structure) == "malicious"
    assert rule_label(one_digit) == "suspicious"
    assert rule_label(strong) == "malicious"
    assert rule_label(homoglyph) == "suspicious"
    assert rule_label(homoglyph_lure) == "malicious"
    assert rule_label(deep_generic) == "suspicious"


def test_matrix_keeps_missing_brand_values_as_nan() -> None:
    matrix = matrix_from_features(
        [{column: None if column == "edit_distance" else 0 for column in MODEL_FEATURE_COLUMNS}]
    )

    assert np.isnan(matrix[0, MODEL_FEATURE_COLUMNS.index("edit_distance")])
    assert matrix[0, MODEL_FEATURE_COLUMNS.index("url_length")] == 0
    assert set(MODEL_FEATURE_COLUMNS).isdisjoint(METADATA_COLUMNS)


def test_grouped_split_does_not_divide_a_group() -> None:
    groups = [f"brand:{index // 5}" for index in range(90)]
    labels = ["legitimate", "suspicious", "malicious"] * 30
    roles = assign_grouped_splits(groups, labels, 20261015)
    seen: dict[str, str] = {}
    for group, role in zip(groups, roles):
        assert seen.setdefault(group, role) == role

    assert set(roles) == {"train", "validation", "test"}
    assert (roles == "train").sum() > (roles == "test").sum()


def test_saved_bundle_matches_recorded_test_predictions() -> None:
    bundle = load_bundle(BUNDLE_PATH)
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    recorded = metrics["test_predictions"]
    extracted = [extract_url_features(item["url"]) for item in recorded]
    replayed = predict_feature_rows(bundle, extracted)

    assert bundle["probabilities_calibrated"] is False
    assert bundle["brand_selection"] == "automatic"
    assert tuple(bundle["feature_columns"]) == MODEL_FEATURE_COLUMNS
    mismatches = [
        item["record_id"]
        for item, result in zip(recorded, replayed)
        if result["predicted_label"] != item["predicted_label"]
    ]
    assert mismatches == []
    selected = metrics["selected_model"]
    correct = sum(item["true_label"] == item["predicted_label"] for item in recorded)
    assert correct / len(recorded) == pytest.approx(metrics["test"][selected]["accuracy"])


def test_saved_model_scores_a_url_without_reading_a_label() -> None:
    bundle = load_bundle(BUNDLE_PATH)
    result = predict_url(bundle, "https://login.paypal.test/account/settings")
    malformed = predict_url(bundle, "not a url")

    assert result["predicted_label"] in {"legitimate", "suspicious", "malicious"}
    assert result["probabilities_calibrated"] is False
    assert "label" not in result["features"]
    assert malformed["parse_error"] == "unusable_url"
    assert malformed["predicted_label"] in {"legitimate", "suspicious", "malicious"}
    assert LIVE_MODEL.is_file()
    assert LIVE_MODEL.stat().st_size == 3644548
