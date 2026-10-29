#!/usr/bin/env python3
"""Run a local, explicitly non-official Phase 2 smoke evaluation on the demo fixture."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from run_inventory import build_predictions, classify_algorithm, validate_predictions, write_predictions
from scripts.evaluate_inventory import evaluate


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_baseline(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["asset_id", "predicted_label"])
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "asset_id": row["asset_id"],
                # Deliberately simple reference baseline: classify the algorithm
                # string only, without role/parameter consistency validation.
                "predicted_label": classify_algorithm(
                    row.get("algorithm", ""),
                    row.get("key_size_or_parameter_set", ""),
                ),
            })


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=str(ROOT / "examples" / "inventory_dev.csv"))
    parser.add_argument("--ground-truth", default=str(ROOT / "examples" / "inventory_dev_labels.csv"))
    parser.add_argument("--output-dir", default=str(ROOT / "results" / "tables"))
    args = parser.parse_args()

    input_path = Path(args.input)
    truth_path = Path(args.ground_truth)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    prediction_path = output_dir / "inventory_dev_predictions.csv"
    baseline_path = output_dir / "inventory_dev_baseline_predictions.csv"
    predictions = build_predictions(input_path)
    validate_predictions(predictions, input_path)
    write_predictions(prediction_path, predictions)
    source_rows = _read_rows(input_path)
    _write_baseline(baseline_path, source_rows)

    project_metrics = evaluate(truth_path, prediction_path)
    baseline_metrics = evaluate(truth_path, baseline_path)
    accuracy_delta = round(project_metrics["accuracy"] - baseline_metrics["accuracy"], 6)
    f1_delta = round(
        project_metrics["macro_f1_present_classes"] - baseline_metrics["macro_f1_present_classes"],
        6,
    )
    result = {
        "evaluation_status": "LOCAL_SMOKE_ONLY_NOT_OFFICIAL",
        "dataset": str(input_path.relative_to(ROOT)) if input_path.is_relative_to(ROOT) else str(input_path),
        "ground_truth": str(truth_path.relative_to(ROOT)) if truth_path.is_relative_to(ROOT) else str(truth_path),
        "rows": len(source_rows),
        "prediction_output": str(prediction_path.relative_to(ROOT)) if prediction_path.is_relative_to(ROOT) else str(prediction_path),
        "baseline_prediction_output": str(baseline_path.relative_to(ROOT)) if baseline_path.is_relative_to(ROOT) else str(baseline_path),
        "project_metrics": project_metrics,
        "baseline": {
            "name": "algorithm-name-only baseline",
            "description": "Uses classify_algorithm only; it does not check role consistency or parameter mismatches.",
            "metrics": baseline_metrics,
        },
        "comparison": {
            "accuracy_delta_vs_baseline": accuracy_delta,
            "macro_f1_present_classes_delta_vs_baseline": f1_delta,
        },
        "limitations": [
            "The development CSV is a synthetic regression fixture, not the organizer's P2_inventory/inventory_dev.csv.",
            "The labels are expected outputs for a small rule-regression fixture, not independently sampled organizer ground truth.",
            "These metrics are smoke-test evidence only and must not be presented as official hackathon scores.",
            "The organizer's baseline_classifier.py and evaluate.py are not present in this checkout.",
        ],
    }
    metrics_path = ROOT / "results" / "inventory_eval_metrics.json"
    comparison_path = ROOT / "results" / "tables" / "inventory_baseline_comparison.json"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    comparison_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "evaluation_status": result["evaluation_status"],
        "rows": len(source_rows),
        "project_accuracy": project_metrics["accuracy"],
        "baseline_accuracy": baseline_metrics["accuracy"],
        "accuracy_delta": accuracy_delta,
        "metrics_file": str(metrics_path.relative_to(ROOT)),
        "baseline_comparison_file": str(comparison_path.relative_to(ROOT)),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
