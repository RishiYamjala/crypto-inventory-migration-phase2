import pandas as pd
import pytest

from scripts.benchmark_inventory import run_benchmark
from scripts.evaluate_inventory import evaluate


def test_evaluation_reports_accuracy_precision_recall_fp_and_fn(tmp_path):
    truth = tmp_path / "truth.csv"
    predictions = tmp_path / "predictions.csv"
    pd.DataFrame([
        {"asset_id": "a", "true_label": "QUANTUM_VULNERABLE"},
        {"asset_id": "b", "true_label": "QUANTUM_RESISTANT"},
        {"asset_id": "c", "true_label": "LEGACY_BROKEN"},
        {"asset_id": "d", "true_label": "UNKNOWN"},
    ]).to_csv(truth, index=False)
    pd.DataFrame([
        {"asset_id": "a", "predicted_label": "QUANTUM_VULNERABLE"},
        {"asset_id": "b", "predicted_label": "QUANTUM_VULNERABLE"},
        {"asset_id": "c", "predicted_label": "LEGACY_BROKEN"},
        {"asset_id": "d", "predicted_label": "UNKNOWN"},
    ]).to_csv(predictions, index=False)

    report = evaluate(truth, predictions)
    assert report["dataset_rows"] == 4
    assert report["accuracy"] == 0.75
    assert report["per_class"]["QUANTUM_VULNERABLE"]["false_positive"] == 1
    assert report["per_class"]["QUANTUM_RESISTANT"]["false_negative"] == 1
    assert report["per_class"]["LEGACY_BROKEN"]["precision"] == 1.0


def test_evaluator_rejects_mismatched_ids_and_unknown_labels(tmp_path):
    truth = tmp_path / "truth.csv"
    predictions = tmp_path / "predictions.csv"
    pd.DataFrame([{"asset_id": "a", "true_label": "UNKNOWN"}]).to_csv(truth, index=False)
    pd.DataFrame([{"asset_id": "b", "predicted_label": "UNKNOWN"}]).to_csv(predictions, index=False)
    with pytest.raises(ValueError, match="IDs must match exactly"):
        evaluate(truth, predictions)

    pd.DataFrame([{"asset_id": "a", "predicted_label": "SAFE"}]).to_csv(predictions, index=False)
    with pytest.raises(ValueError, match="unsupported labels"):
        evaluate(truth, predictions)


def test_scale_benchmark_validates_every_requested_row_count():
    results = run_benchmark([100, 250])
    assert [item["rows"] for item in results] == [100, 250]
    assert all(item["validation"] == "passed" for item in results)
    assert all(item["wall_seconds"] >= 0 for item in results)
    assert all(item["rows_per_second"] > 0 for item in results)
