from pathlib import Path

import pytest

from src.discovery import discover_directory


def test_discovery_reports_target_algorithms_with_line_evidence_and_migration(tmp_path):
    sample = tmp_path / "tls.conf"
    sample.write_text(
        "certificate uses RSA-2048 and SHA-256\n"
        "openssl genrsa -out server.key 2048\n"
        "algorithm = ML-DSA\n"
        "signature = ec.ECDSA(hash_algorithm)\n"
        "curve = secp256r1\n"
        "kex = Diffie-Hellman\n"
        "signer = dsa.generate_private_key()\n",
        encoding="utf-8",
    )
    found = discover_directory(tmp_path)
    assert {"RSA-2048", "ECDSA", "ECC", "DH", "DSA"}.issubset(set(found["algorithm"]))
    assert set(found["evidence_source"]) == {"tls.conf"}
    assert found["line_number"].gt(0).all()
    assert found["evidence_excerpt"].notna().all()
    assert found["fips_migration"].notna().all()
    assert "SHA-256" not in set(found["algorithm"])
    assert "ML-DSA" not in set(found["algorithm"])


def test_discovery_reports_repeated_algorithm_on_distinct_lines(tmp_path):
    (tmp_path / "keys.py").write_text(
        "key_a = rsa.generate_private_key()\nkey_b = rsa.generate_private_key()\n",
        encoding="utf-8",
    )
    found = discover_directory(tmp_path)
    rsa_rows = found[found["algorithm"] == "RSA"]
    assert list(rsa_rows["line_number"]) == [1, 2]


def test_discovery_rejects_missing_directory(tmp_path):
    with pytest.raises(NotADirectoryError):
        discover_directory(tmp_path / "does-not-exist")


def test_discovery_skips_symlink_files(tmp_path):
    root = tmp_path / "authorized"
    root.mkdir()
    outside = tmp_path / "outside-secret.conf"
    outside.write_text("RSA-2048", encoding="utf-8")
    link = root / "linked.conf"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlinks unavailable in this environment: {exc}")
    assert discover_directory(root).empty

def test_discovery_covers_requested_algorithm_families(tmp_path):
    (tmp_path / "crypto.py").write_text(
        "rsa.generate_private_key()\n"
        "openssl genrsa -out rsa3072.key 3072\n"
        "dsa.generate_private_key()\n"
        "dh.generate_parameters(generator=2, key_size=2048)\n"
        "ec.generate_private_key(ec.SECP256R1())\n"
        "private_key.exchange(ec.ECDH(), peer_key)\n"
        "curve = X25519\n",
        encoding="utf-8",
    )
    found = discover_directory(tmp_path)
    algorithms = set(found["algorithm"])
    assert {"RSA", "RSA-3072", "DSA", "DH", "ECDH", "ECC"}.issubset(algorithms)

def test_generic_ec_private_key_generation_is_not_assumed_to_be_ecdh(tmp_path):
    (tmp_path / "keys.py").write_text(
        "key = ec.generate_private_key(ec.SECP256R1())\\n", encoding="utf-8"
    )
    found = discover_directory(tmp_path)
    assert "ECDH" not in set(found["algorithm"])
    assert "ECC" in set(found["algorithm"])
