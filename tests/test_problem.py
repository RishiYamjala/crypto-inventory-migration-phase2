import pandas as pd

from src.problem import migration_for, score_inventory


def row(asset_name, algorithm, usage):
    return pd.Series({
        "asset_name": asset_name,
        "algorithm": algorithm,
        "usage": usage,
        "sensitivity": "High",
        "lifespan": "5-10 years",
    })


def test_key_exchange_does_not_use_signature_algorithm():
    recommendation, _ = migration_for(row("Employee VPN", "ECDH P-256", "VPN"))
    assert "ML-KEM" in recommendation
    assert "ML-DSA" not in recommendation


def test_signature_use_does_not_use_kem_alone():
    recommendation, _ = migration_for(row("Code Signing", "ECDSA P-256", "Code Signing"))
    assert "ML-DSA" in recommendation
    assert "ML-KEM" not in recommendation


def test_tls_certificate_covers_both_roles():
    recommendation, effort = migration_for(row("Customer Portal Certificate", "RSA-2048", "TLS/HTTPS"))
    assert "ML-KEM" in recommendation and "ML-DSA" in recommendation
    assert effort == "High"


def test_rsa_tls_role_review_does_not_depend_on_asset_name():
    from src.problem import algorithm_role

    for asset_name in ["Web Server", "Customer Portal", "TLS Certificate"]:
        item = row(asset_name, "RSA-2048", "TLS/HTTPS")
        recommendation, effort = migration_for(item)
        role = algorithm_role(item["algorithm"], item["usage"])
        assert "Review RSA role" in recommendation
        assert "ML-KEM" in recommendation and "ML-DSA" in recommendation
        assert effort == "High"
        assert "role review required" in role


def test_rsa_tls_does_not_return_no_action_for_non_certificate_name():
    recommendation, effort = migration_for(row("Web Server", "RSA-3072", "TLS/HTTPS"))
    assert recommendation != "No action"
    assert effort != "None"


def test_scored_inventory_contains_explainable_priority_fields(tmp_path):
    df = score_inventory("data/raw/inventory.csv", tmp_path)
    assert len(df) == 10
    assert list(df["priority_rank"]) == list(range(1, 11))
    assert df["risk_rationale"].notna().all()
    assert (tmp_path / "migration_plan.csv").exists()



def test_scanner_algorithm_labels_have_migration_recommendations():
    from src.problem import vulnerability_score

    assert vulnerability_score("ECC") > 0
    assert "ML-KEM" in migration_for(row("Key agreement", "ECDH", "VPN"))[0]
    assert "ML-DSA" in migration_for(row("Signer", "ECDSA", "Digital Signatures"))[0]
    assert "Confirm ECC role" in migration_for(row("Curve", "ECC", "Configuration Evidence"))[0]
    assert "Confirm RSA role" in migration_for(row("RSA asset", "RSA", "VPN"))[0]
