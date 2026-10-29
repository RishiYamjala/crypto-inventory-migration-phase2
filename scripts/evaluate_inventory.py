"""Evaluate inventory classifications against a manually verified labeled CSV.

Ground truth CSV contract: asset_id,true_label
Prediction CSV contract: asset_id,predicted_label

This tool computes metrics only for rows with a one-to-one ID match. It never
creates labels or treats unreviewed scanner candidates as ground truth.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

LABELS = (
    "QUANTUM_VULNERABLE",
    "QUANTUM_RESISTANT",
    "HYBRID",
    "SYMMETRIC_OR_HASH",
    "LEGACY_BROKEN",
    "UNKNOWN",
)


def evaluate(ground_truth_path: str | Path, predictions_path: str | Path) -> dict:
    truth = pd.read_csv(ground_truth_path, dtype=str, keep_default_na=False)
    pred = pd.read_csv(predictions_path, dtype=str, keep_default_na=False)
    required_truth = {"asset_id", "true_label"}
    required_pred = {"asset_id", "predicted_label"}
    if not required_truth.issubset(truth.columns):
        raise ValueError(f"Ground truth must contain columns: {sorted(required_truth)}")
    if not required_pred.issubset(pred.columns):
        raise ValueError(f"Predictions must contain columns: {sorted(required_pred)}")
    for name, frame, label_col in (
        ("ground truth", truth, "true_label"),
        ("predictions", pred, "predicted_label"),
    ):
        if frame["asset_id"].str.strip().eq("").any():
            raise ValueError(f"{name} contains blank asset_id values")
        if frame["asset_id"].duplicated().any():
            raise ValueError(f"{name} contains duplicate asset_id values")
        invalid = sorted(set(frame[label_col]) - set(LABELS))
        if invalid:
            raise ValueError(f"{name} contains unsupported labels: {invalid}")
    truth_ids, pred_ids = set(truth.asset_id), set(pred.asset_id)
    if truth_ids != pred_ids:
        missing_predictions = sorted(truth_ids - pred_ids)
        extra_predictions = sorted(pred_ids - truth_ids)
        raise ValueError(
            "Ground-truth/prediction asset IDs must match exactly; "
            f"missing_predictions={missing_predictions[:10]}, "
            f"extra_predictions={extra_predictions[:10]}"
        )
    merged = truth.merge(pred, on="asset_id", how="inner", validate="one_to_one")
    n = len(merged)
    if n == 0:
        raise ValueError("Cannot evaluate an empty labeled dataset")
    y_true = merged.true_label.tolist()
    y_pred = merged.predicted_label.tolist()
    correct = sum(a == b for a, b in zip(y_true, y_pred))
    per_class = {}
    for label in LABELS:
        tp = sum(a == label and b == label for a, b in zip(y_true, y_pred))
        fp = sum(a != label and b == label for a, b in zip(y_true, y_pred))
        fn = sum(a == label and b != label for a, b in zip(y_true, y_pred))
        tn = n - tp - fp - fn
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        specificity = tn / (tn + fp) if tn + fp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {
            "support": sum(a == label for a in y_true),
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "specificity": round(specificity, 6),
            "f1": round(f1, 6),
        }
    present = [v for v in per_class.values() if v["support"] > 0]
    return {
        "dataset_rows": n,
        "accuracy": round(correct / n, 6),
        "macro_precision_present_classes": round(sum(v["precision"] for v in present) / len(present), 6),
        "macro_recall_present_classes": round(sum(v["recall"] for v in present) / len(present), 6),
        "macro_f1_present_classes": round(sum(v["f1"] for v in present) / len(present), 6),
        "per_class": per_class,
        "interpretation_note": (
            "Metrics describe only the supplied manually labeled rows. They are not official "
            "evaluation results unless the labels and evaluation protocol are official."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", required=True, help="CSV with asset_id,true_label")
    parser.add_argument("--predictions", required=True, help="CSV with asset_id,predicted_label")
    parser.add_argument("--output", help="Optional JSON output path; otherwise print to stdout")
    args = parser.parse_args()
    report = evaluate(args.ground_truth, args.predictions)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
