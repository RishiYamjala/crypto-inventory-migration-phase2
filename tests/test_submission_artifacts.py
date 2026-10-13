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
