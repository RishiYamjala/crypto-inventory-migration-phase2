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
