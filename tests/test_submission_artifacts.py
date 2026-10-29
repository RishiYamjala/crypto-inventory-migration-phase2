"""Sanity checks for committed participant-defined processor models."""
import json
from pathlib import Path

from processors.processor_A import build_processor as build_a
from processors.processor_B import build_processor as build_b

ROOT = Path(__file__).resolve().parents[1]


def test_processor_models_match_their_generators():
    for filename, builder in [
        ("processor_A.json", build_a),
        ("processor_B.json", build_b),
    ]:
        committed = json.loads((ROOT / "processors" / filename).read_text(encoding="utf-8"))
        assert committed == builder()


def test_processor_qubit_counts_and_coupling_edges_are_valid():
    expected = {"processor_A.json": 5, "processor_B.json": 9}
    for filename, qubit_count in expected.items():
        config = json.loads((ROOT / "processors" / filename).read_text(encoding="utf-8"))
        assert config["num_qubits"] == qubit_count
        assert config["official_challenge_kit_verified"] is False
        assert config["coupling_map"]
        for edge in config["coupling_map"]:
            assert len(edge) == 2
            assert edge[0] != edge[1]
            assert all(isinstance(node, int) and 0 <= node < qubit_count for node in edge)

def test_platform_manifest_and_runtime_capture_script_are_present():
    import json

    manifest = json.loads((ROOT / "platform_A_info.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1.0"
    assert manifest["capture_status"] == "runtime_captured"
    assert manifest["platform"]["system"] == "Linux"
    assert manifest["python"]["version"] == "3.12.15"
    assert manifest["official_environment_check"]["status"] == "not_run"
    assert (ROOT / "scripts" / "capture_platform_info.py").is_file()


def test_local_inventory_fixture_labels_match_ids_and_are_disclosed_as_synthetic():
    import csv

    with (ROOT / "examples" / "inventory_dev.csv").open(newline="", encoding="utf-8") as handle:
        inventory = list(csv.DictReader(handle))
    with (ROOT / "examples" / "inventory_dev_labels.csv").open(newline="", encoding="utf-8") as handle:
        labels = list(csv.DictReader(handle))
    assert len(inventory) == 11
    assert [row["asset_id"] for row in inventory] == [row["asset_id"] for row in labels]
    assert {row["true_label"] for row in labels} == {
        "QUANTUM_VULNERABLE", "QUANTUM_RESISTANT", "HYBRID",
        "SYMMETRIC_OR_HASH", "LEGACY_BROKEN", "UNKNOWN",
    }

def test_smoke_evaluation_entrypoint_and_vetted_dependency_pins_are_present():
    root = ROOT
    assert (root / "scripts" / "run_phase2_smoke_evaluation.py").is_file()
    requirements = (root / "requirements.txt").read_text(encoding="utf-8")
    assert "cryptography==50.0.2" in requirements
    assert "pqcrypto==0.4.0" in requirements

