import csv
from pathlib import Path

import pytest

from run_inventory import (
    LABELS, OUTPUT_COLUMNS, build_predictions, classify_algorithm, classify_record,
    validate_predictions,
)


def write_csv(path, rows, headers=None):
    headers = headers or list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("RSA-2048", "QUANTUM_VULNERABLE"), ("SHA256withRSA", "QUANTUM_VULNERABLE"),
        ("SHA-256", "SYMMETRIC_OR_HASH"), ("MD5", "LEGACY_BROKEN"),
        ("3DES", "LEGACY_BROKEN"), ("ML-KEM-768", "QUANTUM_RESISTANT"),
        ("ML-DSA-44", "QUANTUM_RESISTANT"), ("FN-DSA-512", "QUANTUM_RESISTANT"),
        ("LMS", "QUANTUM_RESISTANT"), ("XMSS", "QUANTUM_RESISTANT"),
        ("ECDSA-P256+ML-DSA-44", "HYBRID"), ("X25519+ML-KEM-768", "HYBRID"),
        ("vendor-managed", "UNKNOWN"), ("", "UNKNOWN"),
    ],
)
def test_algorithm_families(algorithm, expected):
    assert classify_algorithm(algorithm) == expected


def test_hash_declared_as_signature_is_unknown():
    assert classify_record({"algorithm": "SHA-256", "primitive": "digital_signature"}) == "UNKNOWN"


def test_classical_algorithm_declared_as_hash_is_unknown():
    assert classify_record({"algorithm": "RSA-2048", "primitive": "hash"}) == "UNKNOWN"


def test_invalid_explicit_pqc_parameter_is_unknown():
    assert classify_record({
        "algorithm": "ML-KEM", "primitive": "key_establishment",
        "key_size_or_parameter_set": "2048",
    }) == "UNKNOWN"


def test_missing_parameter_for_encoded_standardized_name_is_allowed():
    assert classify_record({
        "algorithm": "ML-KEM-768", "primitive": "key_establishment",
        "key_size_or_parameter_set": "",
    }) == "QUANTUM_RESISTANT"


def test_schema_columns_and_exact_wave_values(tmp_path):
    source = write_csv(tmp_path / "inventory.csv", [
        {"asset_id": "a1", "algorithm": "RSA-2048", "primitive": "digital_signature",
         "data_retention_years": "15", "internet_exposed": "yes", "criticality": "high"},
        {"asset_id": "a2", "algorithm": "ML-KEM-768", "primitive": "key_establishment",
         "data_retention_years": "2", "internet_exposed": "no", "criticality": "medium"},
        {"asset_id": "a3", "algorithm": "vendor-managed"},
    ])
    predictions = build_predictions(source)
    validate_predictions(predictions, source)
    assert list(predictions[0]) == OUTPUT_COLUMNS
    assert len(predictions) == 3
    assert all(row["predicted_label"] in LABELS for row in predictions)
    assert {row["migration_wave"] for row in predictions} == {"Wave 1", "Wave 3", "review"}
    assert sorted(row["priority_rank"] for row in predictions) == [1, 2, 3]
    assert predictions[2]["migration_wave"] == "review"


def test_missing_or_duplicate_asset_ids_are_rejected(tmp_path):
    path = write_csv(tmp_path / "bad.csv", [
        {"asset_id": "dup", "algorithm": "RSA"},
        {"asset_id": "dup", "algorithm": "AES-256"},
    ])
    with pytest.raises(ValueError, match="unique"):
        build_predictions(path)
    path = write_csv(tmp_path / "blank.csv", [{"asset_id": "", "algorithm": "RSA"}])
    with pytest.raises(ValueError, match="nonblank"):
        build_predictions(path)


def test_legacy_inventory_without_asset_id_gets_stable_ids_and_valid_dependencies(tmp_path):
    path = write_csv(tmp_path / "legacy.csv", [
        {"asset_name": "Customer Portal Certificate", "algorithm": "RSA-2048",
         "depends_on": "Employee VPN;not-a-real-id"},
        {"asset_name": "Employee VPN", "algorithm": "ECDH P-256", "depends_on": ""},
        {"asset_name": "Customer Portal Certificate", "algorithm": "AES-256",
         "depends_on": "Employee VPN"},
    ])
    first = build_predictions(path)
    second = build_predictions(path)
    validate_predictions(first, path)
    assert [row["asset_id"] for row in first] == [
        "customer-portal-certificate", "employee-vpn", "customer-portal-certificate-2",
    ]
    assert first == second
    assert first[0]["depends_on"] == "employee-vpn"
    assert first[2]["depends_on"] == "employee-vpn"


def test_embedded_and_explicit_pqc_parameters_must_agree():
    assert classify_record({
        "algorithm": "ML-KEM-768", "primitive": "key_establishment",
        "key_size_or_parameter_set": "1024",
    }) == "UNKNOWN"


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
    assert classify_record({"algorithm": algorithm, "primitive": primitive}) == expected


def test_post_quantum_parameter_sets():
    assert classify_record({"algorithm": "FN-DSA-512", "primitive": "digital_signature",
                            "key_size_or_parameter_set": "512"}) == "QUANTUM_RESISTANT"
    assert classify_record({"algorithm": "FN-DSA-512", "primitive": "digital_signature",
                            "key_size_or_parameter_set": "1024"}) == "UNKNOWN"
    assert classify_record({"algorithm": "HQC-128", "primitive": "key_establishment",
                            "key_size_or_parameter_set": "256"}) == "UNKNOWN"
    assert classify_record({"algorithm": "SLH-DSA-SHA2-128s", "primitive": "digital_signature",
                            "key_size_or_parameter_set": "SHA2-128s"}) == "QUANTUM_RESISTANT"


def test_ambiguous_duplicate_asset_names_are_not_guessed_as_dependencies(tmp_path):
    path = write_csv(tmp_path / "ambiguous.csv", [
        {"asset_name": "Shared Name", "algorithm": "RSA-2048", "depends_on": ""},
        {"asset_name": "Shared Name", "algorithm": "AES-256", "depends_on": ""},
        {"asset_name": "Consumer", "algorithm": "AES-256", "depends_on": "Shared Name"},
    ])
    predictions = build_predictions(path)
    validate_predictions(predictions, path)
    assert predictions[2]["depends_on"] == ""


def test_empty_inventory_rejected(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("asset_id,algorithm\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at least one data row"):
        build_predictions(path)
