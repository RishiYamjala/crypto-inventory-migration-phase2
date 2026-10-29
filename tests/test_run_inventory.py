import pandas as pd
import pytest

from run_inventory import (
    LABELS,
    OUTPUT_COLUMNS,
    _parameter_issue,
    _role,
    _yes,
    build_predictions,
    classify_algorithm,
    classify_record,
    validate_predictions,
)


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("RSA-4096", "QUANTUM_VULNERABLE"),
        ("DSA-2048", "QUANTUM_VULNERABLE"),
        ("DH-2048", "QUANTUM_VULNERABLE"),
        ("DH2048", "QUANTUM_VULNERABLE"),
        ("ECDSA P-521", "QUANTUM_VULNERABLE"),
        ("ffdhe2048", "QUANTUM_VULNERABLE"),
        ("ML-KEM-768", "QUANTUM_RESISTANT"),
        ("Kyber-768", "QUANTUM_RESISTANT"),
        ("ML-DSA-65", "QUANTUM_RESISTANT"),
        ("Dilithium3", "QUANTUM_RESISTANT"),
        ("SLH-DSA-SHA2-128s", "QUANTUM_RESISTANT"),
        ("FN-DSA-512", "QUANTUM_RESISTANT"),
        ("Falcon-1024", "QUANTUM_RESISTANT"),
        ("HQC-128", "QUANTUM_RESISTANT"),
        ("LMS", "QUANTUM_RESISTANT"),
        ("XMSS", "QUANTUM_RESISTANT"),
        ("X25519MLKEM768", "HYBRID"),
        ("mlkem768x25519-sha256", "HYBRID"),
        ("RSA+ML-DSA-65", "HYBRID"),
        ("AES-256-GCM", "SYMMETRIC_OR_HASH"),
        ("ChaCha20-Poly1305", "SYMMETRIC_OR_HASH"),
        ("SHA-512", "SYMMETRIC_OR_HASH"),
        ("DES", "LEGACY_BROKEN"),
        ("DES-CBC", "LEGACY_BROKEN"),
        ("DES-ECB", "LEGACY_BROKEN"),
        ("DESede", "LEGACY_BROKEN"),
        ("RC4", "LEGACY_BROKEN"),
        ("Vendor Custom Crypto", "UNKNOWN"),
        ("", "UNKNOWN"),
        (None, "UNKNOWN"),
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
    ],
)
def test_role_and_algorithm_consistency(role, algorithm, expected):
    row = pd.Series({"algorithm": algorithm, "primitive": role})
    assert classify_record(row) == expected


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("key establishment", "key_establishment"),
        ("key_encapsulation", "key_establishment"),
        ("signature generation", "digital_signature"),
        ("asymmetric signature", "digital_signature"),
        ("block cipher", "symmetric_encryption"),
        ("message authentication code", "mac"),
        ("key derivation function", "kdf"),
        ("digest", "hash"),
    ],
)
def test_role_aliases(role, expected):
    assert _role(role) == expected


@pytest.mark.parametrize(
    ("algorithm", "params", "invalid"),
    [
        ("ML-KEM-768", "768", False),
        ("ML-KEM-768", "512", True),
        ("ML-DSA-65", "65", False),
        ("ML-DSA-65", "87", True),
        ("FN-DSA-512", "512", False),
        ("FN-DSA-512", "1024", True),
        ("HQC-128", "128", False),
        ("HQC-128", "256", True),
        ("SLH-DSA", "SHA2-128s", False),
        ("SLH-DSA", "not-a-parameter", True),
        ("LMS", "LMS_SHA256_M32_H10", False),
        ("LMS", "bogus", True),
        ("XMSS", "XMSS-SHA2_10_256", False),
        ("XMSS", "bogus", True),
        ("AES-256-GCM", "256", False),
        ("AES-256-GCM", "512", True),
        ("RSA-2048", "2048", False),
        ("RSA-2048", "1024", False),
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


def test_predictions_schema_ranks_waves_dependencies_and_unknowns(tmp_path):
    source = tmp_path / "inventory.csv"
    output_path = tmp_path / "predictions.csv"
    pd.DataFrame([
        {
            "asset_id": "edge", "algorithm": "RSA-2048", "primitive": "key establishment",
            "internet_exposed": "yes", "retention": "permanent", "criticality": "critical",
            "data_sensitivity": "restricted", "depends_on": "db;missing",
        },
        {
            "asset_id": "db", "algorithm": "ML-KEM-768", "primitive": "key establishment",
            "internet_exposed": "no", "retention": "2 years", "criticality": "low",
            "data_sensitivity": "public",
        },
        {"asset_id": "unknown", "algorithm": "vendor cipher"},
        {"asset_id": "legacy", "algorithm": "DES-CBC", "primitive": "symmetric encryption"},
    ]).to_csv(source, index=False)

    output = build_predictions(source)
    assert list(output.columns) == OUTPUT_COLUMNS
    assert len(output) == 4
    assert output["asset_id"].tolist() == ["edge", "db", "unknown", "legacy"]
    assert set(output["predicted_label"]) <= LABELS
    assert output["migration_wave"].isin({"1", "2", "3", "review"}).all()
    assert output.loc[output.asset_id == "unknown", "migration_wave"].item() == "review"
    assert output.loc[output.asset_id == "legacy", "migration_wave"].item() == "1"
    assert output.loc[output.asset_id == "edge", "depends_on"].item() == "db"
    assert sorted(output["priority_rank"].tolist()) == [1, 2, 3, 4]
    assert output["priority_score"].between(0, 100).all()
    assert output["recommended_action"].str.strip().ne("").all()
    assert output["rationale"].str.strip().ne("").all()

    validate_predictions(output, source)
    output.to_csv(output_path, index=False)
    assert output_path.exists()


def test_common_spreadsheet_header_aliases_are_supported(tmp_path):
    source = tmp_path / "aliases.csv"
    pd.DataFrame([{
        "Asset Name": "Public API", "Algorithm Name": "RSA-2048",
        "Primitive Type": "key establishment", "Internet Facing": "yes",
        "Data Retention": "18 months", "Business Criticality": "high",
        "Data Classification": "confidential",
    }]).to_csv(source, index=False)
    output = build_predictions(source)
    assert output.loc[0, "asset_id"] == "public-api"
    assert output.loc[0, "predicted_label"] == "QUANTUM_VULNERABLE"
    assert output.loc[0, "priority_score"] > 50
    validate_predictions(output, source)


def test_duplicate_or_blank_asset_ids_are_rejected(tmp_path):
    duplicate = tmp_path / "duplicate.csv"
    pd.DataFrame([
        {"asset_id": "same", "algorithm": "RSA"},
        {"asset_id": "same", "algorithm": "AES"},
    ]).to_csv(duplicate, index=False)
    with pytest.raises(ValueError, match="unique"):
        build_predictions(duplicate)

    blank = tmp_path / "blank.csv"
    pd.DataFrame([{"asset_id": "", "algorithm": "RSA"}]).to_csv(blank, index=False)
    with pytest.raises(ValueError, match="nonblank"):
        build_predictions(blank)


def test_validator_rejects_bad_wave_rank_and_missing_columns(tmp_path):
    source = tmp_path / "input.csv"
    pd.DataFrame([{"asset_id": "a", "algorithm": "RSA-2048"}]).to_csv(source, index=False)
    output = build_predictions(source)

    bad_wave = output.copy()
    bad_wave.loc[0, "migration_wave"] = "Wave 1"
    with pytest.raises(ValueError, match="migration_wave"):
        validate_predictions(bad_wave)

    bad_rank = output.copy()
    bad_rank.loc[0, "priority_rank"] = 0
    with pytest.raises(ValueError, match="priority_rank"):
        validate_predictions(bad_rank)

    with pytest.raises(ValueError, match="Missing output columns"):
        validate_predictions(output.drop(columns=["rationale"]))


def test_input_requires_recognized_algorithm_column(tmp_path):
    source = tmp_path / "bad.csv"
    pd.DataFrame([{"name": "asset"}]).to_csv(source, index=False)
    with pytest.raises(ValueError, match="algorithm"):
        build_predictions(source)


def test_large_inventory_is_deterministic_and_complete(tmp_path):
    source = tmp_path / "large.csv"
    rows = [
        {
            "asset_id": f"asset-{i:04d}",
            "algorithm": ("RSA-2048", "ML-KEM-768", "AES-256", "DES-CBC", "Vendor Crypto")[i % 5],
            "primitive": ("key establishment", "key establishment", "symmetric encryption", "symmetric encryption", "unknown")[i % 5],
            "internet_exposed": ("yes", "no", "unknown")[i % 3],
            "retention": ("1 year", "5 years", "permanent")[i % 3],
            "criticality": ("low", "medium", "high", "critical")[i % 4],
            "data_sensitivity": ("public", "internal", "confidential")[i % 3],
        }
        for i in range(1000)
    ]
    pd.DataFrame(rows).to_csv(source, index=False)
    first = build_predictions(source)
    second = build_predictions(source)
    assert len(first) == 1000
    assert first.equals(second)
    validate_predictions(first, source)



def test_parameter_validation_rejects_suffix_lookalikes_and_conflicts():
    assert _parameter_issue("ML-KEM-768", "untrusted-768") is True
    assert _parameter_issue("ML-KEM-768", "ML-KEM-768") is False
    assert _parameter_issue("AES-256-GCM", "128") is True
    assert _parameter_issue("AES-256-GCM", "256") is False


def test_algorithm_substring_does_not_create_false_pqc_match():
    assert classify_algorithm("FILMS") == "UNKNOWN"
    assert classify_algorithm("XMSS-SHA2_10_256") == "QUANTUM_RESISTANT"
    assert classify_algorithm("X25519+ML-KEM-768") == "HYBRID"


def test_conflicting_alias_columns_are_rejected(tmp_path):
    source = tmp_path / "conflicting-columns.csv"
    pd.DataFrame([{
        "asset_id": "a",
        "algorithm": "RSA-2048",
        "Algorithm Name": "ML-KEM-768",
    }]).to_csv(source, index=False)
    with pytest.raises(ValueError, match="Ambiguous input schema"):
        build_predictions(source)


def test_csv_values_with_commas_and_semicolons_are_not_used_as_algorithm_aliases(tmp_path):
    source = tmp_path / "punctuation.csv"
    pd.DataFrame([
        {"asset_id": "a", "algorithm": "RSA-2048", "depends_on": "b;missing,not-an-id"},
        {"asset_id": "b", "algorithm": "ML-KEM-768"},
    ]).to_csv(source, index=False)
    result = build_predictions(source)
    validate_predictions(result, source)
    assert result.loc[result.asset_id == "a", "depends_on"].item() == "b"
