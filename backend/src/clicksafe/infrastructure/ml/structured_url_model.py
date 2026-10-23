"""Train-time and predict-time adapter for the structured URL model.

Feature values come from structured_url_features. This module does not read
labels or generation metadata. The scan loads the saved bundle through
StructuredUrlClassifier. Probability outputs are not calibrated.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.model_selection import StratifiedGroupKFold

from clicksafe.infrastructure.ml.structured_url_features import (
    METADATA_COLUMNS,
    MODEL_FEATURE_COLUMNS,
    UrlFeatures,
    extract_url_features,
)

MODEL_VERSION = "2.0.0"
NULL_FILL_VALUE = -1.0
DISPLAY_LABELS = ("legitimate", "suspicious", "malicious")
SELECTION_ORDER = (
    "rule_baseline",
    "logistic_regression",
    "random_forest",
    "hist_gradient_boosting",
)
FP_MARGIN = 0.005
F1_TIE = 0.01

_COLUMN = {name: index for index, name in enumerate(MODEL_FEATURE_COLUMNS)}
_SUBSTITUTION = _COLUMN["character_substitution_count"]
_INSERTION = _COLUMN["character_insertion_indicator"]
_DELETION = _COLUMN["character_deletion_indicator"]
_TRANSPOSITION = _COLUMN["character_transposition_indicator"]
_HOMOGLYPH = _COLUMN["homoglyph_indicator"]
_PUNYCODE = _COLUMN["punycode_indicator"]
_DOUBLE_N = _COLUMN["double_n_for_m_indicator"]
_RN = _COLUMN["rn_for_m_indicator"]
_DISTANCE = _COLUMN["edit_distance"]
_KEYWORDS = _COLUMN["suspicious_keyword_count"]
_BRAND_IN_SUBDOMAIN = _COLUMN["brand_in_subdomain"]
_MISLEADING = _COLUMN["misleading_domain_structure"]
_SUBDOMAINS = _COLUMN["subdomain_count"]


def assert_feature_schema() -> None:
    if set(MODEL_FEATURE_COLUMNS) & set(METADATA_COLUMNS):
        raise RuntimeError("Model features overlap label metadata.")


def matrix_from_features(rows: Sequence[Mapping[str, object]]) -> np.ndarray:
    """Build the model matrix. None stays NaN so a later imputer can see it."""

    assert_feature_schema()
    matrix = np.empty((len(rows), len(MODEL_FEATURE_COLUMNS)), dtype=np.float64)
    for row_index, row in enumerate(rows):
        for column_index, column in enumerate(MODEL_FEATURE_COLUMNS):
            value = row[column]
            matrix[row_index, column_index] = np.nan if value is None else float(value)
    return matrix


def assign_grouped_splits(
    groups: Sequence[str],
    labels: Sequence[str],
    seed: int,
) -> np.ndarray:
    """Put every row in train, validation, or test.

    StratifiedGroupKFold keeps a split_group entirely inside one split and
    tries to preserve class proportions. Five folds become 60% train, 20%
    validation, and 20% test.
    """

    groups_array = np.asarray(groups)
    labels_array = np.asarray(labels)
    if len(groups_array) != len(labels_array):
        raise ValueError("groups and labels must have the same length.")
    folder = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    fold_ids = np.empty(len(labels_array), dtype=int)
    blank = np.zeros(len(labels_array))
    for fold_id, (_, held_out) in enumerate(folder.split(blank, labels_array, groups_array)):
        fold_ids[held_out] = fold_id
    roles = np.full(len(labels_array), "train", dtype=object)
    roles[fold_ids == 0] = "test"
    roles[fold_ids == 1] = "validation"
    _assert_groups_intact(groups_array, roles)
    return roles


def _assert_groups_intact(groups: np.ndarray, roles: np.ndarray) -> None:
    seen: dict[str, str] = {}
    for group, role in zip(groups, roles):
        previous = seen.get(str(group))
        if previous is None:
            seen[str(group)] = str(role)
        elif previous != role:
            raise RuntimeError(f"Group {group} appears in both {previous} and {role}.")


def select_model(validation: Mapping[str, Mapping[str, float]]) -> tuple[str, str]:
    """Choose a model from validation scores.

    Eligible models keep the legitimate-to-malicious rate within 0.5 percentage
    points of the rule baseline. Among those, the highest macro-F1 wins. Models
    within 0.01 macro-F1 of that best score are tied, and the tie break prefers
    the rule, then logistic regression, then random forest, then boosting.
    """

    rule_rate = float(validation["rule_baseline"]["legitimate_as_malicious_rate"])
    eligible = [
        name
        for name in SELECTION_ORDER
        if float(validation[name]["legitimate_as_malicious_rate"]) <= rule_rate + FP_MARGIN
    ]
    if not eligible:
        return (
            "rule_baseline",
            "No learned model stayed within 0.5 percentage points of the rule "
            "baseline legitimate-to-malicious rate on validation.",
        )
    best = max(float(validation[name]["macro_f1"]) for name in eligible)
    near = [name for name in eligible if best - float(validation[name]["macro_f1"]) <= F1_TIE]
    chosen = near[0]
    return (
        chosen,
        "Selected on validation macro-F1 with the legitimate-to-malicious "
        f"constraint. Best eligible macro-F1 was {best:.4f}. Tied models within "
        f"{F1_TIE:.2f} were {', '.join(near)}.",
    )


def _absent(value: float) -> float:
    if value != value:
        return 0.0
    return float(value)


def rule_label(values: np.ndarray) -> str:
    """Map one raw feature row to the published synthetic label rules.

    NaN brand measurements count as absent. A keyword by itself does not make
    a row malicious.
    """

    substitution = _absent(values[_SUBSTITUTION])
    spelling = any(_absent(values[index]) >= 1 for index in (_INSERTION, _DELETION, _TRANSPOSITION))
    script = _absent(values[_HOMOGLYPH]) >= 1 or _absent(values[_PUNYCODE]) >= 1
    double_n = _absent(values[_DOUBLE_N]) >= 1
    rn_pair = _absent(values[_RN]) >= 1
    keywords = _absent(values[_KEYWORDS])
    in_subdomain = _absent(values[_BRAND_IN_SUBDOMAIN]) >= 1
    misleading = _absent(values[_MISLEADING]) >= 1
    structure = in_subdomain or misleading
    brand_missing = values[_DISTANCE] != values[_DISTANCE]
    subdomains = _absent(values[_SUBDOMAINS])
    if keywords >= 1 and (substitution >= 2 or spelling or script or double_n or structure):
        return "malicious"
    mild = (
        substitution >= 1
        or spelling
        or double_n
        or rn_pair
        or script
        or structure
        or (brand_missing and keywords >= 2 and misleading)
        or (brand_missing and subdomains >= 4 and keywords == 0)
    )
    if mild:
        return "suspicious"
    return "legitimate"


class SyntheticRuleBaseline(ClassifierMixin, BaseEstimator):
    """Interpretable baseline. It does not emit probabilities."""

    def fit(self, features: np.ndarray, labels: Sequence[str]) -> SyntheticRuleBaseline:
        del features
        self.classes_ = np.unique(labels)
        self.n_features_in_ = len(MODEL_FEATURE_COLUMNS)
        return self

    def predict(self, features: np.ndarray) -> np.ndarray:
        return np.array([rule_label(row) for row in np.asarray(features)], dtype=object)


def load_bundle(path: Path) -> dict[str, object]:
    import joblib

    bundle = joblib.load(path)
    if not isinstance(bundle, dict):
        raise TypeError("Structured model bundle must be a dictionary.")
    if bundle.get("probabilities_calibrated") is not False:
        raise RuntimeError("Bundle claims calibrated probabilities without a recorded method.")
    columns = tuple(bundle["feature_columns"])
    if columns != MODEL_FEATURE_COLUMNS:
        raise RuntimeError("Saved feature columns do not match the current feature schema.")
    assert_feature_schema()
    return bundle


def predict_feature_rows(
    bundle: Mapping[str, object],
    extracted: Sequence[UrlFeatures],
) -> list[dict[str, object]]:
    pipeline = bundle["pipeline"]
    matrix = matrix_from_features([item.features for item in extracted])
    predicted = pipeline.predict(matrix)
    probabilities = _probability_rows(pipeline, matrix)
    results: list[dict[str, object]] = []
    for index, item in enumerate(extracted):
        results.append(
            {
                "predicted_label": str(predicted[index]),
                "probabilities": probabilities[index],
                "probabilities_calibrated": False,
                "parse_error": item.parse_error,
                "brand_name": item.brand_name,
                "brand_token": item.brand_token,
                "match_reason": item.match_reason,
                "features": dict(item.features),
                "model_version": bundle.get("model_version"),
                "model_type": bundle.get("model_type"),
            }
        )
    return results


def predict_url(bundle: Mapping[str, object], url: str) -> dict[str, object]:
    return predict_feature_rows(bundle, [extract_url_features(url)])[0]


def _probability_rows(pipeline: object, matrix: np.ndarray) -> list[dict[str, float] | None]:
    model = pipeline.named_steps["model"]  # type: ignore[attr-defined]
    if isinstance(model, SyntheticRuleBaseline) or not hasattr(pipeline, "predict_proba"):
        return [None] * len(matrix)
    try:
        scores = pipeline.predict_proba(matrix)  # type: ignore[attr-defined]
    except Exception:
        return [None] * len(matrix)
    classes = [str(label) for label in pipeline.classes_]  # type: ignore[attr-defined]
    rows: list[dict[str, float] | None] = []
    for score in scores:
        rows.append({label: float(value) for label, value in zip(classes, score)})
    return rows
