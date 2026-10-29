import pandas as pd

from run_inventory import LABELS, build_predictions, classify_algorithm


def test_algorithm_families_and_conservative_unknowns():
    cases = {
        "RSA-4096": "QUANTUM_VULNERABLE",
        "DSA-2048": "QUANTUM_VULNERABLE",
        "DH-2048": "QUANTUM_VULNERABLE",
        "ECDSA P-521": "QUANTUM_VULNERABLE",
        "ffdhe2048": "QUANTUM_VULNERABLE",
        "ML-KEM-768": "QUANTUM_RESISTANT",
        "ML-DSA-65": "QUANTUM_RESISTANT",
        "SLH-DSA": "QUANTUM_RESISTANT",
        "X25519MLKEM768": "HYBRID",
        "mlkem768x25519-sha256": "HYBRID",
        "AES-256-GCM": "SYMMETRIC_OR_HASH",
        "ChaCha20-Poly1305": "SYMMETRIC_OR_HASH",
        "SHA-512": "SYMMETRIC_OR_HASH",
        "DES": "LEGACY_BROKEN",
        "DES-CBC": "LEGACY_BROKEN",
        "DES-ECB": "LEGACY_BROKEN",
        "DESede": "LEGACY_BROKEN",
        "RC4": "LEGACY_BROKEN",
        "Vendor Custom Crypto": "UNKNOWN",
        "": "UNKNOWN",
        None: "UNKNOWN",
    }
    assert all(classify_algorithm(value) == expected for value, expected in cases.items())
    assert set(cases.values()) <= LABELS


def test_predictions_include_required_columns_safe_unknown_and_ranks(tmp_path):
    source = tmp_path / "input.csv"
    target = tmp_path / "predictions.csv"
    pd.DataFrame([
        {"asset_id": "a", "algorithm": "RSA-2048", "internet_exposed": "yes", "retention": "permanent", "criticality": "critical"},
        {"asset_id": "b", "algorithm": "vendor cipher", "internet_exposed": "no", "retention": "2 years", "criticality": "low"},
        {"asset_id": "c", "algorithm": "AES-128", "internet_exposed": "no", "retention": "5 years", "criticality": "medium"},
    ]).to_csv(source, index=False)
    output = build_predictions(source)
    required = {"asset_id", "predicted_label", "priority_score", "priority_rank", "recommended_action", "migration_wave", "depends_on", "rationale"}
    assert required <= set(output.columns)
    assert output.loc[output.asset_id == "b", "predicted_label"].item() == "UNKNOWN"
    assert output.loc[output.asset_id == "b", "migration_wave"].item() == "review"
    assert sorted(output.priority_rank) == [1, 2, 3]
    assert output.loc[output.asset_id == "a", "priority_score"].item() == 100
    assert classify_algorithm("DES-ECB") == "LEGACY_BROKEN"
    from run_inventory import _yes
    assert _yes("internet-facing") is True
    assert _yes("public-facing") is True
    assert _yes("not internet-facing") is False
    output.to_csv(target, index=False)
    assert target.exists()


def test_input_requires_algorithm_column(tmp_path):
    source = tmp_path / "bad.csv"
    pd.DataFrame([{"name": "asset"}]).to_csv(source, index=False)
    try:
        build_predictions(source)
    except ValueError as exc:
        assert "algorithm" in str(exc)
    else:
        raise AssertionError("expected missing algorithm column to fail")
