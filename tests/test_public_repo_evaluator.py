import pytest

from scripts.evaluate_public_repo import _read_ground_truth, calculate_metrics


REPO = "psf/requests"
REF = "v2.34.2"


def test_metrics_include_false_positives_and_reviewed_missed_positives():
    detections = {("a.py", "RSA"), ("b.py", "ECDSA")}
    annotations = {
        ("a.py", "RSA"): True,
        ("b.py", "ECDSA"): False,
        ("c.py", "DH"): True,
    }
    result = calculate_metrics(detections, annotations)
    assert result["true_positives"] == 1
    assert result["false_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["precision"] == pytest.approx(0.5)
    assert result["recall"] == pytest.approx(0.5)


def test_metrics_refuse_unreviewed_detection_pairs():
    with pytest.raises(ValueError, match="Every detected pair must be reviewed"):
        calculate_metrics({("a.py", "RSA")}, {})


def test_metrics_leave_precision_and_recall_undefined_without_examples():
    result = calculate_metrics(set(), {})
    assert result["precision"] is None
    assert result["recall"] is None


def _write_truth(path, rows):
    path.write_text(
        "repository,ref,path,algorithm,is_present,reviewed\n" + rows,
        encoding="utf-8",
    )


def test_ground_truth_rejects_unreviewed_rows(tmp_path):
    path = tmp_path / "truth.csv"
    _write_truth(path, "psf/requests,v2.34.2,a.py,RSA,true,false\n")
    with pytest.raises(ValueError, match="not marked reviewed"):
        _read_ground_truth(path, REPO, REF)


def test_ground_truth_rejects_duplicate_path_algorithm_pairs(tmp_path):
    path = tmp_path / "truth.csv"
    _write_truth(
        path,
        "psf/requests,v2.34.2,a.py,RSA,true,true\n"
        "psf/requests,v2.34.2,a.py,RSA,false,true\n",
    )
    with pytest.raises(ValueError, match="Duplicate ground-truth pair"):
        _read_ground_truth(path, REPO, REF)


def test_ground_truth_rejects_a_different_repository_or_ref(tmp_path):
    path = tmp_path / "truth.csv"
    _write_truth(path, "psf/requests,main,a.py,RSA,true,true\n")
    with pytest.raises(ValueError, match="expected 'psf/requests'@'v2.34.2'"):
        _read_ground_truth(path, REPO, REF)
