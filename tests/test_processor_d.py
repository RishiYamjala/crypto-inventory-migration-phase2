import json
from pathlib import Path

from processors.processor_D import build_processor as build_d
from validate_processors import validate

ROOT = Path(__file__).resolve().parents[1]
PROCESSOR_D = ROOT / "processors" / "processor_D.json"


def test_processor_d_is_a_valid_twelve_qubit_research_model():
    errors, data = validate(PROCESSOR_D, expected_qubits=12)
    assert errors == []
    assert data["name"] == "Processor D"
    assert data["num_qubits"] == 12
    assert data["official_challenge_kit_verified"] is False
    assert len(data["coupling_map"]) == 14
    assert data["graph_properties"] == {
        "undirected_edge_count": 14,
        "triangle_count": 0,
        "diameter": 5,
    }


def test_processor_d_json_matches_generator():
    data = json.loads(PROCESSOR_D.read_text(encoding="utf-8"))
    assert data == build_d()


def test_processor_d_edges_are_valid_and_unique():
    data = json.loads(PROCESSOR_D.read_text(encoding="utf-8"))
    edges = [tuple(sorted(edge)) for edge in data["coupling_map"]]
    assert len(edges) == len(set(edges))
    assert all(
        len(edge) == 2 and edge[0] != edge[1]
        and 0 <= edge[0] < 12 and 0 <= edge[1] < 12
        for edge in edges
    )
