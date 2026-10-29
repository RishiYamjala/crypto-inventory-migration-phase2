"""Smoke tests for vetted cryptography package APIs."""
from scripts.crypto_library_selftest import run_self_tests


def test_vetted_library_round_trips():
    report = run_self_tests()
    assert report["status"] == "passed"
    assert report["primitives_implemented_in_project"] is False
    assert all(report["tests"].values())
    assert report["library_versions"]["cryptography"]
    assert report["library_versions"]["pqcrypto"]
