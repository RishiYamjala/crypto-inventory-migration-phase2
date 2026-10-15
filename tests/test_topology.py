from itertools import combinations

from src.processors import load_processor
from src.routing import bidirectional_coupling_map


def _undirected_edges(processor):
    return {tuple(sorted(edge)) for edge in processor["coupling_map"]}


def _triangle_count(processor):
    edges = _undirected_edges(processor)
    nodes = range(processor["num_qubits"])
    return sum(
        1 for a, b, c in combinations(nodes, 3)
        if tuple(sorted((a, b))) in edges
        and tuple(sorted((b, c))) in edges
        and tuple(sorted((a, c))) in edges
    )


def test_processor_qubit_counts_and_basis_gates_match_guide():
    a = load_processor("processors/processor_A.json")
    b = load_processor("processors/processor_B.json")
    assert a["num_qubits"] == 5
    assert b["num_qubits"] == 9
    assert a["graph_properties"] == {"undirected_edge_count": 4, "triangle_count": 0, "diameter": 3}
    assert b["graph_properties"] == {"undirected_edge_count": 12, "triangle_count": 2, "diameter": 4}
    assert a["basis_gates"] == b["basis_gates"] == ["rz", "sx", "x", "cx"]
    for processor in (a, b):
        assert processor["noise"] == {
            "one_qubit_depolarizing": 0.001,
            "cx_depolarizing": 0.005,
            "readout_error": 0.01,
        }


def test_processor_b_graph_is_connected_12_edge_design_with_two_triangles():
    b = load_processor("processors/processor_B.json")
    edges = _undirected_edges(b)
    assert len(edges) == 12
    assert _triangle_count(b) == 2
    seen = {0}
    changed = True
    while changed:
        changed = False
        for a, c in edges:
            if a in seen and c not in seen:
                seen.add(c)
                changed = True
            if c in seen and a not in seen:
                seen.add(a)
                changed = True
    assert seen == set(range(9))


def test_undirected_couplings_are_expanded_both_ways_for_qiskit():
    b = load_processor("processors/processor_B.json")
    directed = bidirectional_coupling_map(b)
    directed_set = {tuple(edge) for edge in directed}
    assert len(directed) == 24
    for a, c in b["coupling_map"]:
        assert (a, c) in directed_set
        assert (c, a) in directed_set
