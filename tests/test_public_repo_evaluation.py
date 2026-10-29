import pytest

from scripts.evaluate_public_repo import calculate_metrics


def test_metrics_count_true_false_positives_and_false_negatives():
    detections = {("a.py", "RSA-2048"), ("b.py", "AES-256")}
    annotations = {
        ("a.py", "RSA-2048"): True,
        ("b.py", "AES-256"): False,
        ("missed.py", "ECDSA P-256"): True,
    }
    result = calculate_metrics(detections, annotations)
    assert result["true_positives"] == 1
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["precision"] == pytest.approx(0.5)
    assert result["recall"] == pytest.approx(0.5)


def test_metrics_reject_missing_review_labels():
    with pytest.raises(ValueError, match="Every detected pair must be reviewed"):
        calculate_metrics({("a.py", "RSA-2048")}, {})


def test_metrics_return_none_when_denominator_is_zero():
    result = calculate_metrics(set(), {})
    assert result["precision"] is None
    assert result["recall"] is None

def test_tracked_ground_truth_template_matches_evaluator_contract():
    import csv
    from pathlib import Path

    from scripts.evaluate_public_repo import GROUND_TRUTH_COLUMNS

    template = Path(__file__).resolve().parents[1] / "data" / "raw" / "psp2_ground_truth_template.csv"
    with template.open(newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle))

    assert header == ["repository", "ref", "path", "algorithm", "is_present", "reviewed"]
    assert set(header) == GROUND_TRUTH_COLUMNS

