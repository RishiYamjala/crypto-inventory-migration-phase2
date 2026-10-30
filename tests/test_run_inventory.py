import csv
import subprocess
import sys
import time
from pathlib import Path

import pytest

from run_inventory import (
    LABELS, OUTPUT_COLUMNS, _parameter_issue, _role, _score, _yes,
    build_predictions, classify_algorithm, classify_record, validate_predictions,
)

ROOT = Path(__file__).resolve().parents[1]


def write_csv(path, rows, headers=None):
    headers = headers or list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    return path


def row_by_id(rows, asset_id):
    return next(row for row in rows if row["asset_id"] == asset_id)


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("RSA-4096", "QUANTUM_VULNERABLE"), ("DSA-2048", "QUANTUM_VULNERABLE"),
        ("RS256", "QUANTUM_VULNERABLE"), ("ES256", "QUANTUM_VULNERABLE"),
        ("Curve25519", "QUANTUM_VULNERABLE"), ("RSASHA256", "QUANTUM_VULNERABLE"),
        ("DH-2048", "QUANTUM_VULNERABLE"), ("DH2048", "QUANTUM_VULNERABLE"),
        ("ECDSA P-521", "QUANTUM_VULNERABLE"), ("ffdhe2048", "QUANTUM_VULNERABLE"),
        ("X25519", "QUANTUM_VULNERABLE"), ("Ed25519", "QUANTUM_VULNERABLE"),
        ("ML-KEM-768", "QUANTUM_RESISTANT"), ("Kyber-768", "QUANTUM_RESISTANT"),
        ("ML-DSA-65", "QUANTUM_RESISTANT"), ("Dilithium3", "QUANTUM_RESISTANT"),
        ("SLH-DSA-SHA2-128s", "QUANTUM_RESISTANT"), ("FN-DSA-512", "QUANTUM_RESISTANT"),
        ("Falcon-1024", "QUANTUM_RESISTANT"), ("HQC-128", "QUANTUM_RESISTANT"),
        ("LMS", "QUANTUM_RESISTANT"), ("XMSS", "QUANTUM_RESISTANT"),
        ("X25519MLKEM768", "HYBRID"), ("mlkem768x25519-sha256", "HYBRID"),
        ("RSA+ML-DSA-65", "HYBRID"), ("AES-256-GCM", "SYMMETRIC_OR_HASH"),
        ("ChaCha20-Poly1305", "SYMMETRIC_OR_HASH"), ("SHA-512", "SYMMETRIC_OR_HASH"),
        ("MD5", "LEGACY_BROKEN"), ("SHA-1", "LEGACY_BROKEN"),
        ("DES", "LEGACY_BROKEN"), ("DES-CBC", "LEGACY_BROKEN"),
        ("DESede", "LEGACY_BROKEN"), ("RC4", "LEGACY_BROKEN"),
        ("Vendor Custom Crypto", "UNKNOWN"), ("", "UNKNOWN"), (None, "UNKNOWN"),
        ("ML-KEM", "QUANTUM_RESISTANT"), ("ML-DSA", "QUANTUM_RESISTANT"),
    ],
)
def test_algorithm_families_and_conservative_unknowns(algorithm, expected):
    assert classify_algorithm(algorithm) == expected
    assert expected in LABELS


@pytest.mark.parametrize(
    ("role", "algorithm", "expected"),
    [
        ("digital_signature", "LMS", "QUANTUM_RESISTANT"),
        ("signature", "XMSS", "QUANTUM_RESISTANT"),
        ("digital_signature", "ML-DSA-65", "QUANTUM_RESISTANT"),
        ("key_establishment", "ML-KEM-768", "QUANTUM_RESISTANT"),
        ("key exchange", "X25519+ML-KEM-768", "HYBRID"),
        ("digital signature", "RSA+ML-DSA-65", "HYBRID"),
        ("digital_signature", "AES-256", "UNKNOWN"),
        ("key_establishment", "ML-DSA-65", "UNKNOWN"),
        ("digital_signature", "ML-KEM-768", "UNKNOWN"),
        ("symmetric_encryption", "RSA-2048", "UNKNOWN"),
        ("hash", "AES-256", "UNKNOWN"),
        ("public_key_encryption", "RSA-OAEP-2048", "QUANTUM_VULNERABLE"),
    ],
)
def test_role_and_algorithm_consistency(role, algorithm, expected):
    assert classify_record({"algorithm": algorithm, "primitive": role}) == expected


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("key establishment", "key_establishment"), ("key_encapsulation", "key_establishment"),
        ("signature generation", "digital_signature"), ("asymmetric signature", "digital_signature"),
        ("block cipher", "symmetric_encryption"), ("message authentication code", "mac"),
        ("key derivation function", "kdf"), ("digest", "hash"),
    ],
)
def test_role_aliases(role, expected):
    assert _role(role) == expected


@pytest.mark.parametrize(
    ("algorithm", "params", "invalid"),
    [
        ("ML-KEM-768", "768", False), ("ML-KEM-768", "512", True),
        ("ML-DSA-65", "65", False), ("ML-DSA-65", "87", True),
        ("FN-DSA-512", "512", False), ("FN-DSA-512", "1024", True),
        ("HQC-128", "128", False), ("HQC-128", "256", True),
        ("SLH-DSA", "SHA2-128s", False), ("SLH-DSA", "not-a-parameter", True),
        ("LMS", "LMS_SHA256_M32_H10", False), ("LMS", "bogus", True),
        ("XMSS", "XMSS-SHA2_10_256", False), ("XMSS", "bogus", True),
        ("AES-256-GCM", "256", False), ("AES-256-GCM", "128", True),
        ("AES-256-GCM", "512", True), ("RSA-2048", "1024", False),
        ("ML-KEM-768", "untrusted-768", True),
    ],
)
def test_parameter_set_validation(algorithm, params, invalid):
    assert _parameter_issue(algorithm, params) is invalid


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("yes", True), ("Y", True), ("exposed", True), ("public-facing", True),
        ("no", False), ("N", False), ("unexposed", False),
        ("not internet-facing", False), ("unknown", None), ("", None),
    ],
)
def test_exposure_aliases(value, expected):
    assert _yes(value) is expected


def test_exact_score_formula_and_waves(tmp_path):
    source = write_csv(tmp_path / "inventory.csv", [
        {"asset_id": "edge", "algorithm": "RSA-2048", "primitive": "key establishment",
         "internet_exposed": "yes", "retention": "permanent", "criticality": "critical",
         "depends_on": "db;missing"},
        {"asset_id": "db", "algorithm": "ML-KEM-768", "primitive": "key establishment",
         "internet_exposed": "no", "retention": "2 years", "criticality": "low"},
        {"asset_id": "unknown", "algorithm": "vendor cipher"},
        {"asset_id": "legacy", "algorithm": "DES-CBC", "primitive": "symmetric encryption"},
        {"asset_id": "internal-rsa", "algorithm": "RSA-2048", "primitive": "key establishment",
         "internet_exposed": "no", "retention": "6 years", "criticality": "medium"},
    ])
    output = build_predictions(source)
    assert [row["asset_id"] for row in output] == ["edge", "db", "unknown", "legacy", "internal-rsa"]
    assert [row["migration_wave"] for row in output] == ["1", "3", "review", "1", "1"]
    assert row_by_id(output, "edge")["priority_score"] == 100
    assert row_by_id(output, "legacy")["priority_score"] == 87
    assert row_by_id(output, "unknown")["priority_score"] == 72
    assert row_by_id(output, "internal-rsa")["priority_score"] == 78
    assert row_by_id(output, "edge")["depends_on"] == "db"
    assert sorted(row["priority_rank"] for row in output) == [1, 2, 3, 4, 5]
    assert all(row["recommended_action"].strip() and row["rationale"].strip() for row in output)
    assert validate_predictions(output, source) is None


def test_score_accounts_for_sensitivity_and_conservative_missing_metadata():
    row = {"internet_exposed": "yes", "data_retention_years": "10", "criticality": "critical",
           "data_sensitivity": "public"}
    assert _score(row, "QUANTUM_VULNERABLE") == 100
    assert _score(row, "LEGACY_BROKEN") == 98
    assert _score(row, "UNKNOWN") == 83
    assert _score(dict(row, data_sensitivity="restricted"), "UNKNOWN") > _score(row, "UNKNOWN")


def test_common_spreadsheet_header_aliases_and_stable_ids(tmp_path):
    source = write_csv(tmp_path / "aliases.csv", [{
        "Asset Name": "Public API", "Algorithm Name": "RSA-2048",
        "Primitive Type": "key establishment", "Internet Facing": "yes",
        "Data Retention": "18 months", "Business Criticality": "high",
    }])
    output = build_predictions(source)
    assert output[0]["asset_id"] == "public-api"
    assert output[0]["predicted_label"] == "QUANTUM_VULNERABLE"
    assert output[0]["priority_score"] == 92
    validate_predictions(output, source)


def test_duplicate_or_blank_asset_ids_are_rejected(tmp_path):
    duplicate = write_csv(tmp_path / "duplicate.csv", [
        {"asset_id": "same", "algorithm": "RSA"},
        {"asset_id": "same", "algorithm": "AES"},
    ])
    with pytest.raises(ValueError, match="unique"):
        build_predictions(duplicate)
    blank = write_csv(tmp_path / "blank.csv", [{"asset_id": "", "algorithm": "RSA"}])
    with pytest.raises(ValueError, match="nonblank"):
        build_predictions(blank)


def test_validator_rejects_bad_wave_rank_and_missing_columns(tmp_path):
    source = write_csv(tmp_path / "input.csv", [{"asset_id": "a", "algorithm": "RSA-2048"}])
    output = build_predictions(source)
    bad_wave = [dict(output[0], migration_wave="Wave 1")]
    with pytest.raises(ValueError, match="migration_wave"):
        validate_predictions(bad_wave)
    bad_rank = [dict(output[0], priority_rank=0)]
    with pytest.raises(ValueError, match="priority_rank"):
        validate_predictions(bad_rank)
    missing = [{k: v for k, v in output[0].items() if k != "rationale"}]
    with pytest.raises(ValueError, match="Missing output columns"):
        validate_predictions(missing)


def test_input_requires_recognized_algorithm_column(tmp_path):
    source = write_csv(tmp_path / "bad.csv", [{"name": "asset"}])
    with pytest.raises(ValueError, match="algorithm"):
        build_predictions(source)


def test_large_inventory_is_deterministic_and_complete(tmp_path):
    rows = [{
        "asset_id": f"asset-{i:04d}",
        "algorithm": ("RSA-2048", "ML-KEM-768", "AES-256", "DES-CBC", "Vendor Crypto")[i % 5],
        "primitive": ("key establishment", "key establishment", "symmetric encryption", "symmetric encryption", "unknown")[i % 5],
        "internet_exposed": ("yes", "no", "unknown")[i % 3],
        "retention": ("1 year", "5 years", "permanent")[i % 3],
        "criticality": ("low", "medium", "high", "critical")[i % 4],
    } for i in range(1000)]
    source = write_csv(tmp_path / "large.csv", rows)
    first = build_predictions(source)
    second = build_predictions(source)
    assert len(first) == 1000
    assert first == second
    validate_predictions(first, source)


def test_conflicting_alias_columns_are_rejected(tmp_path):
    source = write_csv(tmp_path / "conflicting.csv", [
        {"asset_id": "a", "algorithm": "RSA-2048", "Algorithm Name": "ML-KEM-768"},
    ])
    with pytest.raises(ValueError, match="Ambiguous input schema"):
        build_predictions(source)


def test_cli_runs_end_to_end_and_writes_exact_schema(tmp_path):
    source = write_csv(tmp_path / "input.csv", [
        {"asset_id": "rsa", "algorithm": "RSA-2048", "primitive": "digital_signature"},
        {"asset_id": "pqc", "algorithm": "ML-KEM-768", "primitive": "key_establishment"},
    ])
    output = tmp_path / "nested" / "predictions.csv"
    script = ROOT / "run_inventory.py"
    result = subprocess.run(
        [sys.executable, str(script), "--input", str(source), "--output", str(output)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Wrote 2 predictions" in result.stdout
    with output.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == OUTPUT_COLUMNS
        rows = list(reader)
    assert [row["asset_id"] for row in rows] == ["rsa", "pqc"]


def test_thousand_row_inventory_finishes_within_five_minutes(tmp_path):
    source = write_csv(tmp_path / "large.csv", [{
        "asset_id": f"asset-{i}",
        "algorithm": ("RSA-2048", "AES-256-GCM", "ML-KEM-768", "SHA-256")[i % 4],
        "data_retention_years": ("1", "5", "10", "permanent")[i % 4],
        "internet_exposed": ("yes", "no", "unknown", "yes")[i % 4],
        "criticality": ("low", "medium", "high", "critical")[i % 4],
    } for i in range(1000)])
    started = time.perf_counter()
    predictions = build_predictions(source)
    assert time.perf_counter() - started < 300
    validate_predictions(predictions, source)
    assert len(predictions) == 1000


def test_cli_uses_only_python_standard_library_imports():
    import ast
    source = (ROOT / "run_inventory.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    allowed = {"argparse", "csv", "re", "sys", "pathlib", "typing", "__future__"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed, f"Non-standard-library imports found: {sorted(imported - allowed)}"


# Regression coverage for classifier edge cases fixed in the PQC audit.
def test_sha1_is_legacy_even_when_declared_as_hash():
    assert classify_algorithm("SHA-1") == "LEGACY_BROKEN"
    assert classify_record({"algorithm": "SHA-1", "primitive": "hash"}) == "LEGACY_BROKEN"


@pytest.mark.parametrize("algorithm", [
    "HSS-LMS", "HSS_LMS_SHA256_M32_H10", "LM-OTS", "LMOTS-SHA256-N32-W8",
    "XMSS-SHA2_10_256", "XMSSMT-SHA2_20/256",
])
def test_stateful_hash_based_signature_families_are_recognized(algorithm):
    assert classify_algorithm(algorithm) == "QUANTUM_RESISTANT"


def test_hss_lms_and_lmots_parameter_validation():
    assert _parameter_issue("HSS-LMS", "LMS_SHA256_M32_H10") is False
    assert _parameter_issue("HSS-LMS", "bogus") is True
    assert _parameter_issue("LMOTS", "LMOTS_SHA256_N32_W8") is False
    assert _parameter_issue("LMOTS", "bogus") is True


@pytest.mark.parametrize("algorithm", [
    "HYBRID-ML-KEM-768", "HYBRID-ML-DSA-65", "HYBRID-RSA",
])
def test_incomplete_hybrid_name_is_not_accepted(algorithm):
    assert classify_algorithm(algorithm) == "UNKNOWN"


@pytest.mark.parametrize("algorithm", [
    "X25519+ML-KEM-768", "RSA-3072+ML-DSA-65",
])
def test_hybrid_requires_both_recognized_component_families(algorithm):
    assert classify_algorithm(algorithm) == "HYBRID"


@pytest.mark.parametrize(
    ("algorithm", "params", "expected"),
    [
        ("Dilithium3", "65", False),
        ("Dilithium3", "44", True),
        ("ML-DSA-65", "65", False),
        ("ML-DSA-65", "87", True),
        ("SPHINCS+-SHA2-128s", "SHA2-128s", False),
        ("SPHINCS+-SHA2-128s", "SHAKE-128s", True),
    ],
)
def test_dilithium_and_sphincs_parameter_alias_consistency(algorithm, params, expected):
    assert _parameter_issue(algorithm, params) is expected


# Second-pass regression coverage: parameter checks must never raise and must not reject valid metadata.
@pytest.mark.parametrize("algorithm", ["SHA-1", "SHA1", "sha-1", "SHA-1 (legacy)"])
def test_sha1_spelling_variants_validate_as_hash_records(algorithm):
    assert classify_record({"algorithm": algorithm, "primitive": "hash"}) == "LEGACY_BROKEN"


def test_sha1_is_rejected_for_public_key_roles():
    assert classify_record({"algorithm": "SHA-1", "primitive": "digital_signature"}) == "UNKNOWN"


@pytest.mark.parametrize(
    ("algorithm", "params", "expected"),
    [
        # Prefix on the algorithm, the parameter, both or neither must not change the verdict.
        ("HSS_LMS_SHA256_M32_H10", "LMS_SHA256_M32_H10", False),
        ("HSS_LMS_SHA256_M32_H10", "SHA256_M32_H10", False),
        ("LMS_SHA256_M32_H10", "SHA256_M32_H10", False),
        ("LMS_SHA256_M32_H10", "SHA256_M32_H5", True),
        ("HSS-LMS", "LMS_SHAKE256_M24_H15", False),
        ("XMSS-SHA2_10_256", "SHA2_10_256", False),
        ("XMSS-SHA2_10_256", "XMSS-SHA2_10_256", False),
        ("XMSS-SHA2_10_256", "SHA2_16_256", True),
        ("XMSS", "bogus", True),
        ("LM-OTS", "LMOTS_SHA256_N32_W8", False),
        ("HSS-LM-OTS", "LMOTS_SHA256_N32_W8", False),
        ("LMOTS_SHA256_N32_W8", "SHA256_N32_W8", False),
        ("LMOTS", "LMOTS_SHA256_N32_W3", True),
    ],
)
def test_stateful_hash_signature_parameters_compare_values_not_prefixes(algorithm, params, expected):
    assert _parameter_issue(algorithm, params) is expected


@pytest.mark.parametrize(
    ("algorithm", "params", "expected"),
    [
        ("SPHINCS+-SHA2-128s", "SHA2-128s", False),
        ("SPHINCS+-SHA2-128s", "SHA2-128f", True),
        ("SPHINCS+-SHA2-128s", "SHA2-192s", True),
        ("SPHINCS+-SHA2-128s", "SHAKE-128s", True),
        ("SLH-DSA-SHAKE-256f", "SHAKE-256f", False),
        ("SLH-DSA-SHAKE-256f", "SHA2-256f", True),
        ("SPHINCS+", "SHAKE-192s", False),
        ("SPHINCS+", "bogus", True),
        ("Dilithium2", "44", False),
        ("Dilithium5", "87", False),
        ("Dilithium5", "65", True),
        ("ML-DSA-87", "5", False),
        ("ML-DSA-87", "3", True),
        ("Dilithium3", "ML-DSA-65", False),
        ("ML-KEM-768", "untrusted-768", True),
        ("Kyber768", "ML-KEM-768", False),
        ("Kyber768", "512", True),
        ("Falcon-512", "1024", True),
        ("Falcon-512", "FNDSA512", False),
        ("HQC-128", "HQC-256", True),
    ],
)
def test_legacy_pqc_alias_parameter_consistency_never_raises(algorithm, params, expected):
    assert _parameter_issue(algorithm, params) is expected


@pytest.mark.parametrize(
    ("algorithm", "primitive", "params", "expected"),
    [
        ("SPHINCS+-SHA2-128s", "digital_signature", "SHA2-128s", "QUANTUM_RESISTANT"),
        ("SPHINCS+-SHA2-128s", "digital_signature", "SHAKE-128s", "UNKNOWN"),
        ("Dilithium3", "digital_signature", "44", "UNKNOWN"),
        ("Dilithium3", "digital_signature", "3", "QUANTUM_RESISTANT"),
        ("HSS-LMS", "digital_signature", "LMS_SHA256_M32_H10", "QUANTUM_RESISTANT"),
        ("XMSS-SHA2_10_256", "digital_signature", "SHA2_10_256", "QUANTUM_RESISTANT"),
    ],
)
def test_classify_record_handles_pqc_aliases_end_to_end(algorithm, primitive, params, expected):
    row = {"algorithm": algorithm, "primitive": primitive, "key_size_or_parameter_set": params}
    assert classify_record(row) == expected


def test_hybrid_label_needs_a_classical_and_a_pqc_component():
    for name in ("HYBRID", "Hybrid-KEM", "HYBRID-ML-KEM-768", "HYBRID-RSA", "hybrid signature"):
        assert classify_algorithm(name) == "UNKNOWN", name
    for name in ("HYBRID-X25519-MLKEM768", "RSA+ML-DSA-65", "ECDSA-P256+Dilithium3"):
        assert classify_algorithm(name) == "HYBRID", name
