import json
from pathlib import Path

from validate_processors import validate


ROOT = Path(__file__).resolve().parents[1]
PROCESSOR_D = ROOT / "processors" / "processor_D.json"


def test_processor_d_is_a_valid_eleven_qubit_research_model():
    errors, data = validate(PROCESSOR_D, expected_qubits=11)
    assert errors == []
    assert data["name"] == "Processor D"
    assert data["num_qubits"] == 11
    assert data["official_challenge_kit_verified"] is False
    assert len(data["coupling_map"]) == 13
    assert data["graph_properties"] == {
        "undirected_edge_count": 13,
        "triangle_count": 0,
        "diameter": 5,
    }


def test_processor_d_edges_are_valid_and_unique():
    data = json.loads(PROCESSOR_D.read_text(encoding="utf-8"))
    edges = [tuple(sorted(edge)) for edge in data["coupling_map"]]
    assert len(edges) == len(set(edges))
    assert all(
        len(edge) == 2 and edge[0] != edge[1]
        and 0 <= edge[0] < 11 and 0 <= edge[1] < 11
        for edge in edges
    )
