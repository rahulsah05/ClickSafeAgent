"""Replay the saved structured model on the recorded test URLs.

This does not retrain. It checks that the bundle still emits the labels stored
in models/structured_url_model.metrics.json.

    backend\\venv\\Scripts\\python.exe scripts\\evaluate_structured_model.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = REPO_ROOT / "backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from clicksafe.infrastructure.ml.structured_url_features import extract_url_features  # noqa: E402
from clicksafe.infrastructure.ml.structured_url_model import (  # noqa: E402
    load_bundle,
    predict_feature_rows,
)


def main() -> int:
    bundle_path = REPO_ROOT / "models" / "structured_url_model.joblib"
    metrics_path = REPO_ROOT / "models" / "structured_url_model.metrics.json"
    bundle = load_bundle(bundle_path)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    recorded = metrics["test_predictions"]
    extracted = [extract_url_features(item["url"]) for item in recorded]
    replayed = predict_feature_rows(bundle, extracted)
    mismatches = [
        item["record_id"]
        for item, result in zip(recorded, replayed)
        if result["predicted_label"] != item["predicted_label"]
    ]
    selected = metrics["selected_model"]
    test_scores = metrics["test"][selected]
    print(
        json.dumps(
            {
                "selected_model": selected,
                "test_rows": len(recorded),
                "mismatches": len(mismatches),
                "test_accuracy": test_scores["accuracy"],
                "test_macro_f1": test_scores["macro_f1"],
                "legitimate_as_malicious": test_scores["legitimate_as_malicious"],
                "probabilities_calibrated": bundle["probabilities_calibrated"],
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 1 if mismatches else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
