"""Train and evaluate the structured URL model.

The live ClickSafe model is not replaced. Features come from
clicksafe.infrastructure.ml.structured_url_features with automatic brand
selection, which is the same call a later prediction will make. Labels and
generation metadata are not model inputs.

Selection uses the validation split only. The policy is select_model in
structured_url_model.py. Probabilities are not calibrated.

Run from the repository root:

    backend\\venv\\Scripts\\python.exe scripts\\train_structured_model.py
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = REPO_ROOT / "backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from clicksafe.infrastructure.ml.structured_url_features import (  # noqa: E402
    MODEL_FEATURE_COLUMNS,
    extract_url_features,
    normalize_url,
)
from clicksafe.infrastructure.ml.structured_url_model import (  # noqa: E402
    DISPLAY_LABELS,
    MODEL_VERSION,
    NULL_FILL_VALUE,
    SyntheticRuleBaseline,
    assign_grouped_splits,
    matrix_from_features,
    select_model,
)

LIVE_MODEL = (
    REPO_ROOT
    / "backend"
    / "src"
    / "clicksafe"
    / "infrastructure"
    / "ml"
    / "models"
    / "model.joblib"
)
INDICATOR_NAMES = (
    "character_substitution_count",
    "double_n_for_m_indicator",
    "rn_for_m_indicator",
    "character_insertion_indicator",
    "character_deletion_indicator",
    "character_transposition_indicator",
    "homoglyph_indicator",
    "mixed_script_indicator",
    "punycode_indicator",
    "brand_in_subdomain",
    "misleading_domain_structure",
)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the structured URL model.")
    parser.add_argument("--seed", type=int, default=20261015)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=REPO_ROOT / "ml_data" / "url_dataset.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "models" / "structured_url_model.joblib",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=REPO_ROOT / "MODEL_EVALUATION.md",
    )
    return parser.parse_args(argv)


def load_dataset(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise RuntimeError(f"Dataset is empty: {path}")
    return rows


def extract_matrix(rows: list[dict[str, str]]) -> tuple[np.ndarray, list[dict[str, object]]]:
    extracted: list[dict[str, object]] = []
    feature_rows = []
    for index, row in enumerate(rows, start=1):
        features = extract_url_features(row["url"])
        feature_rows.append(features.features)
        extracted.append(
            {
                "brand_name": features.brand_name or "",
                "match_reason": features.match_reason or "",
                "parse_error": features.parse_error,
            }
        )
        if index % 2000 == 0:
            print(f"extracted {index}", flush=True)
    return matrix_from_features(feature_rows), extracted


def score_predictions(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, object]:
    labels = list(DISPLAY_LABELS)
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )
    legit = labels.index("legitimate")
    suspicious = labels.index("suspicious")
    malicious = labels.index("malicious")
    legit_support = int(matrix[legit].sum())
    malicious_support = int(matrix[malicious].sum())
    legit_as_malicious = int(matrix[legit, malicious])
    malicious_as_legit = int(matrix[malicious, legit])
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(report["macro avg"]["precision"]),
        "macro_recall": float(report["macro avg"]["recall"]),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "per_class": {
            label: {
                "precision": float(report[label]["precision"]),
                "recall": float(report[label]["recall"]),
                "f1": float(report[label]["f1-score"]),
                "support": int(report[label]["support"]),
            }
            for label in labels
        },
        "confusion_matrix": matrix.astype(int).tolist(),
        "labels": labels,
        "legitimate_as_malicious": legit_as_malicious,
        "legitimate_as_suspicious": int(matrix[legit, suspicious]),
        "malicious_as_legitimate": malicious_as_legit,
        "legitimate_as_malicious_rate": _rate(legit_as_malicious, legit_support),
        "malicious_as_legitimate_rate": _rate(malicious_as_legit, malicious_support),
    }


def _rate(count: int, support: int) -> float:
    if support == 0:
        raise RuntimeError("Cannot score a split that has no rows for a required class.")
    return count / support


def make_pipeline(name: str, seed: int) -> Pipeline:
    if name == "rule_baseline":
        return Pipeline([("model", SyntheticRuleBaseline())])
    imputer = SimpleImputer(
        strategy="constant",
        fill_value=NULL_FILL_VALUE,
        add_indicator=True,
    )
    if name == "logistic_regression":
        return Pipeline(
            [
                ("imputer", imputer),
                ("scaler", StandardScaler()),
                ("model", LogisticRegression(max_iter=2000, random_state=seed)),
            ]
        )
    if name == "random_forest":
        return Pipeline(
            [
                ("imputer", imputer),
                (
                    "model",
                    RandomForestClassifier(
                        n_estimators=200,
                        max_depth=12,
                        min_samples_leaf=5,
                        random_state=seed,
                        n_jobs=1,
                    ),
                ),
            ]
        )
    if name == "hist_gradient_boosting":
        return Pipeline(
            [
                ("imputer", imputer),
                (
                    "model",
                    HistGradientBoostingClassifier(
                        max_depth=6,
                        learning_rate=0.1,
                        max_iter=200,
                        random_state=seed,
                    ),
                ),
            ]
        )
    raise ValueError(f"Unknown model {name}")


def candidate_names() -> tuple[str, ...]:
    return (
        "dummy_most_frequent",
        "rule_baseline",
        "logistic_regression",
        "random_forest",
        "hist_gradient_boosting",
    )


def fit_candidate(name: str, seed: int, train_x: np.ndarray, train_y: np.ndarray) -> Pipeline:
    if name == "dummy_most_frequent":
        from sklearn.dummy import DummyClassifier

        pipeline = Pipeline(
            [("model", DummyClassifier(strategy="most_frequent", random_state=seed))]
        )
    else:
        pipeline = make_pipeline(name, seed)
    pipeline.fit(train_x, train_y)
    return pipeline


def split_counts(labels: np.ndarray, roles: np.ndarray) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for role in ("train", "validation", "test"):
        chosen = labels[roles == role]
        counts[role] = {label: int((chosen == label).sum()) for label in DISPLAY_LABELS}
        counts[role]["rows"] = int(chosen.size)
    return counts


def require_all_classes(labels: np.ndarray, roles: np.ndarray) -> None:
    expected = set(DISPLAY_LABELS)
    for role in ("train", "validation", "test"):
        present = set(labels[roles == role])
        if present != expected:
            raise RuntimeError(f"{role} is missing classes: {sorted(expected - present)}")


def group_overlap(groups: np.ndarray, roles: np.ndarray) -> int:
    owned: dict[str, str] = {}
    overlap = 0
    for group, role in zip(groups, roles):
        previous = owned.get(str(group))
        if previous is None:
            owned[str(group)] = str(role)
        elif previous != role:
            overlap += 1
    return overlap


def confusion_examples(
    rows: list[dict[str, str]],
    y_true: np.ndarray,
    y_pred: np.ndarray,
    true_label: str,
    predicted_label: str,
    limit: int,
) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for row, actual, predicted in zip(rows, y_true, y_pred):
        if actual != true_label or predicted != predicted_label:
            continue
        found.append(
            {
                "record_id": row["record_id"],
                "url": row["url"],
                "true_label": str(actual),
                "predicted_label": str(predicted),
                "generation_method": row["generation_method"],
                "brand_name": row["brand_name"],
            }
        )
        if len(found) >= limit:
            break
    return found


def method_slices(
    methods: np.ndarray,
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> list[dict[str, object]]:
    slices: list[dict[str, object]] = []
    for method in sorted(set(methods)):
        mask = methods == method
        support = int(mask.sum())
        correct = int((y_true[mask] == y_pred[mask]).sum())
        slices.append(
            {
                "generation_method": str(method),
                "support": support,
                "correct": correct,
                "accuracy": correct / support if support else 0.0,
            }
        )
    slices.sort(key=lambda item: int(item["support"]), reverse=True)
    return slices


def transformed_feature_names(pipeline: Pipeline) -> list[str]:
    names = list(MODEL_FEATURE_COLUMNS)
    imputer = pipeline.named_steps.get("imputer")
    indicator = getattr(imputer, "indicator_", None)
    if indicator is not None:
        names.extend(f"{MODEL_FEATURE_COLUMNS[index]}__missing" for index in indicator.features_)
    return names


def importance_rows(pipeline: Pipeline) -> list[dict[str, object]]:
    model = pipeline.named_steps["model"]
    names = transformed_feature_names(pipeline)
    if hasattr(model, "feature_importances_"):
        values = np.asarray(model.feature_importances_, dtype=float)
        kind = "impurity importance"
    elif hasattr(model, "coef_"):
        coef = np.asarray(model.coef_, dtype=float)
        classes = [str(label) for label in model.classes_]
        if "malicious" not in classes:
            return []
        values = np.abs(coef[classes.index("malicious")])
        kind = "absolute logistic coefficient for malicious, after scaling"
    else:
        return []
    if len(values) != len(names):
        names = [f"transformed_{index}" for index in range(len(values))]
    order = np.argsort(values)[::-1][:12]
    return [
        {"feature": names[int(index)], "value": float(values[int(index)]), "kind": kind}
        for index in order
    ]


def indicator_counts(matrix: np.ndarray) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in INDICATOR_NAMES:
        column = matrix[:, MODEL_FEATURE_COLUMNS.index(name)]
        present = column[~np.isnan(column)]
        counts[name] = int((present >= 1).sum())
    return counts


def _score_limit(
    test_scores: dict[str, dict[str, object]],
    chosen_test: dict[str, object],
    splits: dict[str, object],
) -> str:
    held_out = splits["held_out_brand_groups"]
    logistic_f1 = float(test_scores["logistic_regression"]["macro_f1"])
    if logistic_f1 >= 1.0 - 1e-9:
        return (
            "Logistic regression test macro-F1 of 1.0000, including on "
            f"{held_out} held-out brand groups, means the three synthetic classes "
            "are linearly separable in these features. That result does not "
            "establish real-world accuracy."
        )
    return (
        f"The selected test macro-F1 is {float(chosen_test['macro_f1']):.4f} on "
        f"{held_out} held-out brand groups. That result does not establish "
        "real-world accuracy."
    )


def render_report(summary: dict[str, object]) -> str:
    dataset = summary["dataset"]
    splits = summary["splits"]
    selected = summary["selected_model"]
    validation = summary["validation"]
    test_scores = summary["test"]
    chosen_test = test_scores[selected]
    lines = [
        "# Structured URL model evaluation",
        "",
        "These figures are from one local training run on the synthetic dataset. "
        "They do not measure real-world phishing detection.",
        "",
        "The saved model is not the live ClickSafe model. Scan verdicts still come "
        "from the existing pipeline. This file does not claim calibrated probabilities.",
        "",
        "## Dataset",
        "",
        "| Measure | Value |",
        "| --- | ---: |",
        f"| Rows | {dataset['rows']} |",
        f"| Unique URLs | {dataset['unique_urls']} |",
        f"| Unique normalized URLs | {dataset['unique_normalized_urls']} |",
        f"| Duplicate normalized URLs | {dataset['duplicate_normalized_urls']} |",
        f"| Unique source brands | {dataset['unique_brands']} |",
        f"| Rows with no source brand | {dataset['blank_brand_rows']} |",
        f"| SHA-256 | `{dataset['sha256']}` |",
        "",
        "Class distribution:",
        "",
        "| Label | Rows |",
        "| --- | ---: |",
    ]
    for label in DISPLAY_LABELS:
        lines.append(f"| {label} | {dataset['label_counts'][label]} |")
    lines.extend(
        [
            "",
            "Scenario distribution (`generation_method` is audit metadata, not a feature):",
            "",
        ]
    )
    lines.append("| generation_method | Rows |")
    lines.append("| --- | ---: |")
    for method, count in dataset["generation_method_counts"]:
        lines.append(f"| {method} | {count} |")
    lines.extend(["", "Rows where a measured indicator is at least 1:", ""])
    lines.append("| Indicator | Rows |")
    lines.append("| --- | ---: |")
    for name, count in dataset["indicator_counts"].items():
        lines.append(f"| {name} | {count} |")
    lines.extend(
        [
            "",
            f"Automatic brand selection disagreed with the source brand on "
            f"{dataset['brand_disagreements']} rows.",
            "",
            "## Split",
            "",
            "Rows are split with `StratifiedGroupKFold` (5 folds, shuffle, "
            f"seed {summary['seed']}). Fold 0 is test, fold 1 is validation, and "
            "folds 2–4 are train. A `split_group` stays in one split. "
            f"Groups that crossed splits: {splits['overlapping_groups']}.",
            "",
            "| Split | Rows | legitimate | suspicious | malicious | Groups |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for role in ("train", "validation", "test"):
        item = splits["counts"][role]
        lines.append(
            f"| {role} | {item['rows']} | {item['legitimate']} | {item['suspicious']} | "
            f"{item['malicious']} | {splits['groups'][role]} |"
        )
    lines.extend(
        [
            "",
            f"Held-out test groups: {splits['held_out_groups']}. "
            f"Of those, {splits['held_out_brand_groups']} are brand groups.",
            "",
            "## Selection",
            "",
            "Candidates are a rule baseline, logistic regression, a random forest, "
            "and histogram gradient boosting. A most-frequent dummy is reported "
            "and is not eligible. Missing brand features stay NaN until a model "
            f"pipeline fills them with {NULL_FILL_VALUE:g} and adds missingness "
            "indicators. The imputer and scaler are fit on the training rows only. "
            "The rule reads the raw NaN matrix and does not impute.",
            "",
            "A model is eligible when its validation legitimate→malicious rate is "
            "at most 0.5 percentage points above the rule. The highest validation "
            "macro-F1 wins. Candidates within 0.01 macro-F1 of that score tie, and "
            "the tie prefers the rule, then logistic regression, then random forest, "
            "then boosting.",
            "",
            summary["selection_reason"],
            "",
            "### Validation",
            "",
            _metrics_table(validation),
            "",
            f"Selected model: `{selected}`.",
            "",
            "## Test",
            "",
            "Test scores did not choose the model.",
            "",
            _metrics_table(test_scores),
            "",
            f"Selected model test accuracy: {chosen_test['accuracy']:.4f}. "
            f"Macro precision: {chosen_test['macro_precision']:.4f}. "
            f"Macro recall: {chosen_test['macro_recall']:.4f}. "
            f"Macro F1: {chosen_test['macro_f1']:.4f}.",
            "",
            "### Per class",
            "",
            "| Class | Precision | Recall | F1 | Support |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for label in DISPLAY_LABELS:
        item = chosen_test["per_class"][label]
        lines.append(
            f"| {label} | {item['precision']:.4f} | {item['recall']:.4f} | "
            f"{item['f1']:.4f} | {item['support']} |"
        )
    lines.extend(["", "### Confusion matrix", "", _confusion_table(chosen_test), ""])
    lines.extend(_example_section(summary))
    lines.extend(["", "### Test rows by scenario", ""])
    lines.append("| generation_method | Support | Correct | Accuracy |")
    lines.append("| --- | ---: | ---: | ---: |")
    for item in summary["method_slices"]:
        lines.append(
            f"| {item['generation_method']} | {item['support']} | {item['correct']} | "
            f"{item['accuracy']:.4f} |"
        )
    lines.extend(["", "## Memorization check", ""])
    random_split = summary["random_split"]
    lines.append(
        "The saved model uses the grouped split. A second, unsaved model of the "
        f"same type was trained on a stratified random {random_split['train_rows']}/"
        f"{random_split['test_rows']} split that can place one brand's rows on both "
        "sides. Its test macro-F1 was "
        f"{random_split['macro_f1']:.4f} and its legitimate→malicious rate was "
        f"{random_split['legitimate_as_malicious_rate']:.4f}. "
        f"The grouped test macro-F1 for the saved model was {chosen_test['macro_f1']:.4f}."
    )
    lines.extend(["", "## Learned signal", ""])
    importances = summary["importances"]
    if importances:
        lines.append(f"Top weights ({importances[0]['kind']}):")
        lines.append("")
        lines.append("| Feature | Value |")
        lines.append("| --- | ---: |")
        for item in importances:
            lines.append(f"| {item['feature']} | {item['value']:.4f} |")
    else:
        lines.append("The selected model does not expose feature weights.")
    lines.extend(
        [
            "",
            "## Saved bundle",
            "",
            f"| Field | Value |",
            f"| --- | --- |",
            f"| Path | `{summary['output']}` |",
            f"| Model version | {MODEL_VERSION} |",
            f"| Model type | {selected} |",
            f"| Feature schema | {summary['feature_schema_version']} |",
            f"| Features | {len(MODEL_FEATURE_COLUMNS)} |",
            f"| Brand selection | automatic |",
            f"| Null fill | {NULL_FILL_VALUE:g} plus missingness indicators for learned models |",
            f"| Probabilities calibrated | false |",
            f"| SHA-256 | `{summary['model_sha256']}` |",
            f"| scikit-learn | {summary['sklearn_version']} |",
            "",
            "Model features:",
            "",
        ]
    )
    for name in MODEL_FEATURE_COLUMNS:
        lines.append(f"- `{name}`")
    lines.extend(
        [
            "",
            "Excluded metadata: `record_id`, `generation_method`, `source_type`, "
            "`label`, `reference_domain`, `split_group`, `transformation_types`.",
            "",
            "## Command",
            "",
            "```powershell",
            "backend\\venv\\Scripts\\python.exe scripts\\train_structured_model.py --seed 20261015",
            "```",
            "",
            "## Limitations",
            "",
            "- The labels were assigned by the synthetic generator. A high score means "
            "those rules are visible in the features. "
            + _score_limit(test_scores, chosen_test, splits),
            "- Every hostname uses a reserved suffix. The suffix is not evidence about "
            "the public web.",
            "- `predict_proba` values, when the saved model has them, are uncalibrated "
            "scores. No calibration step was fit or tested.",
            "- Automatic brand selection can differ from the source brand. This run "
            f"found {dataset['brand_disagreements']} disagreements. Prediction uses "
            "automatic selection, and so does this training matrix.",
            "- The previous file `backend/src/clicksafe/infrastructure/ml/models/model.joblib` "
            "stays in the package. The scan loads this structured bundle as evidence "
            "and does not let it set the verdict.",
            "",
        ]
    )
    return "\n".join(lines)


def _metrics_table(scores: dict[str, dict[str, object]]) -> str:
    header = (
        "| Model | Accuracy | Macro P | Macro R | Macro F1 | Legit→malicious | Malicious→legit |\n"
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"
    )
    body = []
    for name, item in scores.items():
        body.append(
            f"| {name} | {item['accuracy']:.4f} | {item['macro_precision']:.4f} | "
            f"{item['macro_recall']:.4f} | {item['macro_f1']:.4f} | "
            f"{item['legitimate_as_malicious']} ({item['legitimate_as_malicious_rate']:.4f}) | "
            f"{item['malicious_as_legitimate']} ({item['malicious_as_legitimate_rate']:.4f}) |"
        )
    return "\n".join([header, *body])


def _confusion_table(score: dict[str, object]) -> str:
    labels = list(DISPLAY_LABELS)
    matrix = score["confusion_matrix"]
    header = "| true \\ predicted | " + " | ".join(labels) + " |"
    rule = "| --- | " + " | ".join("---:" for _ in labels) + " |"
    body = []
    for index, label in enumerate(labels):
        cells = " | ".join(str(int(value)) for value in matrix[index])
        body.append(f"| {label} | {cells} |")
    return "\n".join([header, rule, *body])


def _example_section(summary: dict[str, object]) -> list[str]:
    chosen = summary["test"][summary["selected_model"]]
    lines = [
        "",
        "### False positives and false negatives",
        "",
        "A false positive here is a test URL labeled legitimate and predicted "
        f"malicious. Count: {chosen['legitimate_as_malicious']}.",
        "",
        "A false negative is a test URL labeled malicious and predicted "
        f"legitimate. Count: {chosen['malicious_as_legitimate']}.",
        "",
        "Legitimate URLs predicted suspicious: "
        f"{chosen['legitimate_as_suspicious']}.",
        "",
    ]
    sections = (
        ("Legitimate predicted malicious", summary["false_positives"]),
        ("Malicious predicted legitimate", summary["false_negatives"]),
        ("Legitimate predicted suspicious", summary["legitimate_as_suspicious_examples"]),
    )
    for title, examples in sections:
        lines.append(f"#### {title}")
        lines.append("")
        if not examples:
            lines.append("None in the test split.")
            lines.append("")
            continue
        lines.append("| record_id | true | predicted | scenario | URL |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in examples:
            lines.append(
                f"| {item['record_id']} | {item['true_label']} | {item['predicted_label']} | "
                f"{item['generation_method']} | `{item['url']}` |"
            )
        lines.append("")
    return lines


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.output.resolve() == LIVE_MODEL.resolve():
        print("Refusing to replace the live ClickSafe model.", file=sys.stderr)
        return 2
    import sklearn

    rows = load_dataset(args.dataset)
    digest = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    labels = np.array([row["label"] for row in rows])
    groups = np.array([row["split_group"] for row in rows])
    methods = np.array([row["generation_method"] for row in rows])
    urls = [normalize_url(row["url"]) for row in rows]
    if len(urls) != len(set(urls)):
        raise RuntimeError("Dataset contains duplicate normalized URLs.")
    print(f"loaded {len(rows)} rows", flush=True)
    matrix, extracted = extract_matrix(rows)
    roles = assign_grouped_splits(groups, labels, args.seed)
    require_all_classes(labels, roles)
    if group_overlap(groups, roles) != 0:
        raise RuntimeError("Grouped split leaked a group across splits.")
    train = roles == "train"
    validation = roles == "validation"
    test = roles == "test"
    names = candidate_names()
    validation_scores: dict[str, dict[str, object]] = {}
    test_scores: dict[str, dict[str, object]] = {}
    fitted: dict[str, Pipeline] = {}
    for name in names:
        print(f"fitting {name}", flush=True)
        pipeline = fit_candidate(name, args.seed, matrix[train], labels[train])
        fitted[name] = pipeline
        validation_scores[name] = score_predictions(
            labels[validation],
            pipeline.predict(matrix[validation]),
        )
        test_scores[name] = score_predictions(labels[test], pipeline.predict(matrix[test]))
        print(
            f"  val macro-F1 {validation_scores[name]['macro_f1']:.4f} "
            f"legit→malicious {validation_scores[name]['legitimate_as_malicious']}",
            flush=True,
        )
    eligible_scores = {
        name: validation_scores[name]
        for name in (
            "rule_baseline",
            "logistic_regression",
            "random_forest",
            "hist_gradient_boosting",
        )
    }
    selected, reason = select_model(eligible_scores)
    print(f"selected {selected}", flush=True)
    saved = fitted[selected]
    test_pred = saved.predict(matrix[test])
    test_rows = [row for row, keep in zip(rows, test) if keep]
    false_positives = confusion_examples(
        test_rows,
        labels[test],
        test_pred,
        "legitimate",
        "malicious",
        8,
    )
    false_negatives = confusion_examples(
        test_rows,
        labels[test],
        test_pred,
        "malicious",
        "legitimate",
        8,
    )
    suspicious_examples = confusion_examples(
        test_rows,
        labels[test],
        test_pred,
        "legitimate",
        "suspicious",
        8,
    )
    random_train, random_test = train_test_split(
        np.arange(len(rows)),
        test_size=0.2,
        random_state=args.seed,
        stratify=labels,
    )
    print("fitting random-split diagnostic", flush=True)
    random_model = fit_candidate(
        selected,
        args.seed,
        matrix[random_train],
        labels[random_train],
    )
    random_scores = score_predictions(
        labels[random_test],
        random_model.predict(matrix[random_test]),
    )
    disagreements = [
        {
            "record_id": row["record_id"],
            "source_brand": row["brand_name"],
            "selected_brand": item["brand_name"],
            "url": row["url"],
        }
        for row, item in zip(rows, extracted)
        if (row["brand_name"] or "") != item["brand_name"]
    ]
    label_counts = Counter(labels.tolist())
    method_counts = Counter(methods.tolist())
    summary: dict[str, object] = {
        "seed": args.seed,
        "sklearn_version": sklearn.__version__,
        "feature_schema_version": "1.0.0",
        "selected_model": selected,
        "selection_reason": reason,
        "output": str(args.output),
        "dataset": {
            "rows": len(rows),
            "unique_urls": len({row["url"] for row in rows}),
            "unique_normalized_urls": len(set(urls)),
            "duplicate_normalized_urls": len(urls) - len(set(urls)),
            "unique_brands": len({row["brand_name"] for row in rows if row["brand_name"]}),
            "blank_brand_rows": sum(not row["brand_name"] for row in rows),
            "sha256": digest,
            "label_counts": {label: int(label_counts[label]) for label in DISPLAY_LABELS},
            "generation_method_counts": method_counts.most_common(),
            "indicator_counts": indicator_counts(matrix),
            "brand_disagreements": len(disagreements),
            "brand_disagreement_examples": disagreements[:10],
        },
        "splits": {
            "counts": split_counts(labels, roles),
            "groups": {
                role: len(set(groups[roles == role])) for role in ("train", "validation", "test")
            },
            "overlapping_groups": group_overlap(groups, roles),
            "held_out_groups": len(
                set(groups[test]) - set(groups[train]) - set(groups[validation])
            ),
            "held_out_brand_groups": len(
                {
                    group
                    for group in set(groups[test]) - set(groups[train]) - set(groups[validation])
                    if str(group).startswith("brand:")
                }
            ),
        },
        "validation": validation_scores,
        "test": test_scores,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "legitimate_as_suspicious_examples": suspicious_examples,
        "method_slices": method_slices(methods[test], labels[test], test_pred),
        "random_split": {
            "train_rows": int(len(random_train)),
            "test_rows": int(len(random_test)),
            "macro_f1": random_scores["macro_f1"],
            "legitimate_as_malicious_rate": random_scores["legitimate_as_malicious_rate"],
            "accuracy": random_scores["accuracy"],
        },
        "importances": importance_rows(saved),
        "test_predictions": [
            {
                "record_id": row["record_id"],
                "url": row["url"],
                "true_label": str(actual),
                "predicted_label": str(predicted),
            }
            for row, actual, predicted in zip(test_rows, labels[test], test_pred)
        ],
    }
    bundle = {
        "model_version": MODEL_VERSION,
        "model_type": selected,
        "feature_schema_version": summary["feature_schema_version"],
        "feature_columns": list(MODEL_FEATURE_COLUMNS),
        "pipeline": saved,
        "labels": list(DISPLAY_LABELS),
        "seed": args.seed,
        "brand_selection": "automatic",
        "probabilities_calibrated": False,
        "null_fill_value": NULL_FILL_VALUE,
        "sklearn_version": sklearn.__version__,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    import joblib

    joblib.dump(bundle, temporary, compress=3)
    temporary.replace(args.output)
    summary["model_sha256"] = hashlib.sha256(args.output.read_bytes()).hexdigest()
    metrics_path = args.output.with_suffix(".metrics.json")
    write_text(metrics_path, json.dumps(summary, indent=2, sort_keys=True) + "\n")
    write_text(args.report, render_report(summary))
    print(
        json.dumps(
            {
                "selected": selected,
                "test_macro_f1": test_scores[selected]["macro_f1"],
                "test_legit_as_malicious": test_scores[selected]["legitimate_as_malicious"],
                "sha256": summary["model_sha256"],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
