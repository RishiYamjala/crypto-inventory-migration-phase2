import pandas as pd
import pytest

from run_inventory import (
    LABELS,
    OUTPUT_COLUMNS,
    build_predictions,
    classify_algorithm,
    classify_record,
    validate_predictions,
)


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("RSA-2048", "QUANTUM_VULNERABLE"),
        ("SHA256withRSA", "QUANTUM_VULNERABLE"),
        ("SHA-256", "SYMMETRIC_OR_HASH"),
        ("MD5", "LEGACY_BROKEN"),
        ("3DES", "LEGACY_BROKEN"),
        ("ML-KEM-768", "QUANTUM_RESISTANT"),
        ("ML-DSA-44", "QUANTUM_RESISTANT"),
        ("FN-DSA", "QUANTUM_RESISTANT"),
        ("LMS", "QUANTUM_RESISTANT"),
        ("XMSS", "QUANTUM_RESISTANT"),
        ("ECDSA-P256+ML-DSA-44", "HYBRID"),
        ("X25519+ML-KEM-768", "HYBRID"),
        ("vendor-managed", "UNKNOWN"),
        ("", "UNKNOWN"),
    ],
)
def test_algorithm_families(algorithm, expected):
    assert classify_algorithm(algorithm) == expected


def test_hash_declared_as_signature_is_unknown():
    row = pd.Series({"algorithm": "SHA-256", "primitive": "digital_signature"})
    assert classify_record(row) == "UNKNOWN"


def test_classical_algorithm_declared_as_hash_is_unknown():
    row = pd.Series({"algorithm": "RSA-2048", "primitive": "hash"})
    assert classify_record(row) == "UNKNOWN"


def test_invalid_explicit_pqc_parameter_is_unknown():
    row = pd.Series({
        "algorithm": "ML-KEM",
        "primitive": "key_establishment",
        "key_size_or_parameter_set": "2048",
    })
    assert classify_record(row) == "UNKNOWN"


def test_missing_parameter_does_not_automatically_make_valid_algorithm_unknown():
    row = pd.Series({
        "algorithm": "ML-KEM-768",
        "primitive": "key_establishment",
        "key_size_or_parameter_set": "",
    })
    assert classify_record(row) == "QUANTUM_RESISTANT"


def test_schema_columns_and_exact_wave_values(tmp_path):
    input_path = tmp_path / "inventory.csv"
    output_path = tmp_path / "predictions.csv"
    pd.DataFrame([
        {
            "asset_id": "a1",
            "algorithm": "RSA-2048",
            "primitive": "digital_signature",
            "key_size_or_parameter_set": "2048",
            "data_retention_years": "15",
            "data_sensitivity": "confidential",
            "internet_exposed": "yes",
            "criticality": "high",
        },
        {
            "asset_id": "a2",
            "algorithm": "ML-KEM-768",
            "primitive": "key_establishment",
            "key_size_or_parameter_set": "768",
            "data_retention_years": "2",
            "data_sensitivity": "internal",
            "internet_exposed": "no",
            "criticality": "medium",
        },
        {
            "asset_id": "a3",
            "algorithm": "vendor-managed",
            "primitive": "unknown",
            "key_size_or_parameter_set": "",
            "data_retention_years": "",
            "data_sensitivity": "",
            "internet_exposed": "",
            "criticality": "",
        },
    ]).to_csv(input_path, index=False)

    predictions = build_predictions(input_path)
    validate_predictions(predictions, input_path)
    predictions.to_csv(output_path, index=False)

    assert output_path.exists()
    assert list(predictions.columns) == OUTPUT_COLUMNS
    assert len(predictions) == 3
    assert set(predictions["predicted_label"]).issubset(LABELS)
    assert set(predictions["migration_wave"]).issubset({"1", "2", "3", "review"})
    assert predictions["priority_rank"].tolist() == [1, 2, 3]
    assert predictions.loc[predictions.asset_id == "a3", "migration_wave"].iloc[0] == "review"


def test_missing_or_duplicate_asset_ids_are_rejected(tmp_path):
    path = tmp_path / "bad.csv"
    pd.DataFrame([
        {"asset_id": "dup", "algorithm": "RSA"},
        {"asset_id": "dup", "algorithm": "AES-256"},
    ]).to_csv(path, index=False)
    with pytest.raises(ValueError, match="unique"):
        build_predictions(path)

    pd.DataFrame([{"asset_id": "", "algorithm": "RSA"}]).to_csv(path, index=False)
    with pytest.raises(ValueError, match="nonblank"):
        build_predictions(path)
