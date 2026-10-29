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
    assert sorted(predictions["priority_rank"].tolist()) == [1, 2, 3]
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



def test_legacy_inventory_without_asset_id_gets_stable_ids_and_valid_dependencies(tmp_path):
    path = tmp_path / "legacy.csv"
    pd.DataFrame([
        {"asset_name": "Customer Portal Certificate", "algorithm": "RSA-2048", "depends_on": "Employee VPN;not-a-real-id"},
        {"asset_name": "Employee VPN", "algorithm": "ECDH P-256", "depends_on": ""},
        {"asset_name": "Customer Portal Certificate", "algorithm": "AES-256", "depends_on": "Employee VPN"},
    ]).to_csv(path, index=False)

    first = build_predictions(path)
    second = build_predictions(path)
    validate_predictions(first, path)

    assert first["asset_id"].tolist() == [
        "customer-portal-certificate",
        "employee-vpn",
        "customer-portal-certificate-2",
    ]
    assert first["asset_id"].tolist() == second["asset_id"].tolist()
    assert first.loc[0, "depends_on"] == "employee-vpn"
    assert first.loc[2, "depends_on"] == "employee-vpn"


def test_embedded_and_explicit_pqc_parameters_must_agree():
    row = pd.Series({
        "algorithm": "ML-KEM-768",
        "primitive": "key_establishment",
        "key_size_or_parameter_set": "1024",
    })
    assert classify_record(row) == "UNKNOWN"



@pytest.mark.parametrize(
    ("algorithm", "primitive", "expected"),
    [
        ("SHA-256", "key_establishment", "UNKNOWN"),
        ("AES-256-GCM", "hash", "UNKNOWN"),
        ("ML-KEM-768", "digital_signature", "UNKNOWN"),
        ("RSA-OAEP-2048", "public_key_encryption", "QUANTUM_VULNERABLE"),
        ("AES-256-GCM", "symmetric_encryption", "SYMMETRIC_OR_HASH"),
        ("HMAC-SHA-256", "mac", "SYMMETRIC_OR_HASH"),
        ("HKDF-SHA-256", "kdf", "SYMMETRIC_OR_HASH"),
    ],
)
def test_role_and_algorithm_consistency(algorithm, primitive, expected):
    row = pd.Series({"algorithm": algorithm, "primitive": primitive})
    assert classify_record(row) == expected


@pytest.mark.parametrize(
    ("algorithm", "params", "expected"),
    [
        ("FN-DSA-512", "1024", "UNKNOWN"),
        ("FN-DSA-512", "512", "QUANTUM_RESISTANT"),
        ("HQC-128", "256", "UNKNOWN"),
        ("HQC-192", "192", "QUANTUM_RESISTANT"),
        ("SLH-DSA-SHA2-128s", "SHA2-128s", "QUANTUM_RESISTANT"),
    ],
)
def test_post_quantum_parameter_sets(algorithm, params, expected):
    row = pd.Series({
        "algorithm": algorithm,
        "primitive": "digital_signature" if "DSA" in algorithm else "key_establishment",
        "key_size_or_parameter_set": params,
    })
    assert classify_record(row) == expected


def test_ambiguous_duplicate_asset_names_are_not_guessed_as_dependencies(tmp_path):
    path = tmp_path / "ambiguous.csv"
    pd.DataFrame([
        {"asset_name": "Shared Name", "algorithm": "RSA-2048", "depends_on": ""},
        {"asset_name": "Shared Name", "algorithm": "AES-256", "depends_on": ""},
        {"asset_name": "Consumer", "algorithm": "AES-256", "depends_on": "Shared Name"},
    ]).to_csv(path, index=False)
    predictions = build_predictions(path)
    validate_predictions(predictions, path)
    assert predictions.loc[2, "depends_on"] == ""



def test_cli_runs_end_to_end_and_writes_schema_csv(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "nested" / "predictions.csv"
    pd.DataFrame([
        {"asset_id": "rsa", "algorithm": "RSA-2048", "primitive": "digital_signature"},
        {"asset_id": "pqc", "algorithm": "ML-KEM-768", "primitive": "key_establishment"},
    ]).to_csv(input_path, index=False)

    script = Path(__file__).resolve().parents[1] / "run_inventory.py"
    result = subprocess.run(
        [sys.executable, str(script), "--input", str(input_path), "--output", str(output_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Wrote 2 predictions" in result.stdout
    output = pd.read_csv(output_path, dtype=object)
    assert list(output.columns) == OUTPUT_COLUMNS
    assert output["asset_id"].tolist() == ["rsa", "pqc"]
    validate_predictions(output, input_path)


def test_thousand_row_inventory_finishes_within_five_minutes(tmp_path):
    import time

    path = tmp_path / "large.csv"
    pd.DataFrame([
        {
            "asset_id": f"asset-{i}",
            "algorithm": ["RSA-2048", "AES-256-GCM", "ML-KEM-768", "SHA-256"][i % 4],
            "data_retention_years": [1, 5, 10, "permanent"][i % 4],
            "data_sensitivity": ["public", "internal", "confidential", "restricted"][i % 4],
            "internet_exposed": ["yes", "no", "unknown", "yes"][i % 4],
            "criticality": ["low", "medium", "high", "critical"][i % 4],
        }
        for i in range(1000)
    ]).to_csv(path, index=False)

    started = time.perf_counter()
    predictions = build_predictions(path)
    elapsed = time.perf_counter() - started

    validate_predictions(predictions, path)
    assert len(predictions) == 1000
    assert elapsed < 300
