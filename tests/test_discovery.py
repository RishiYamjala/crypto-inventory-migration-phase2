from pathlib import Path

import pytest

from src.discovery import discover_directory


def test_discovery_reports_algorithm_evidence_from_authorized_directory(tmp_path):
    sample = tmp_path / "tls.conf"
    sample.write_text("certificate uses RSA-2048 and SHA-256", encoding="utf-8")

    found = discover_directory(tmp_path)

    assert {"RSA-2048", "SHA-256"}.issubset(set(found["algorithm"]))
    assert set(found["evidence_source"]) == {"tls.conf"}
    assert found["evidence_excerpt"].notna().all()


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

    found = discover_directory(root)
    assert found.empty
