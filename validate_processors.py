"""Validate participant-defined processor model structure.

The Master Guide does not provide official Processor A/B JSON files. This
validator checks only the reproducibility and internal consistency of the
participant-defined research models; it does not authenticate hardware.
"""
import json
from pathlib import Path
import networkx as nx

ROOT = Path(__file__).parent
PROCESSORS = {
    "Processor A": (ROOT / "processors" / "processor_A.json", 5),
    "Processor B": (ROOT / "processors" / "processor_B.json", 9),
}
EXPECTED_BASIS = ["rz", "sx", "x", "cx"]
EXPECTED_NOISE = {
    "one_qubit_depolarizing": 0.001,
    "cx_depolarizing": 0.005,
    "readout_error": 0.01,
}


def validate(path, expected_qubits):
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = []
    if data.get("num_qubits") != expected_qubits:
        errors.append(f"expected {expected_qubits} qubits")
    if data.get("basis_gates") != EXPECTED_BASIS:
        errors.append(f"basis_gates must equal {EXPECTED_BASIS}")
    if data.get("noise") != EXPECTED_NOISE:
        errors.append("noise values do not match the guide's required simulator settings")
    edges = data.get("coupling_map", [])
    normalized = set()
    for edge in edges:
        if not isinstance(edge, list) or len(edge) != 2:
            errors.append(f"invalid edge {edge!r}")
            continue
        a, b = edge
        if not isinstance(a, int) or not isinstance(b, int) or a == b:
            errors.append(f"invalid edge {edge!r}")
        elif min(a, b) < 0 or max(a, b) >= expected_qubits:
            errors.append(f"edge outside qubit range: {edge!r}")
        else:
            normalized.add(tuple(sorted((a, b))))
    if len(normalized) != len(edges):
        errors.append("duplicate undirected coupling edge")
    graph = nx.Graph()
    graph.add_nodes_from(range(expected_qubits))
    graph.add_edges_from(normalized)
    if not nx.is_connected(graph):
        errors.append("coupling graph must be connected")
    actual_properties = {
        "undirected_edge_count": graph.number_of_edges(),
        "triangle_count": sum(nx.triangles(graph).values()) // 3,
        "diameter": nx.diameter(graph) if nx.is_connected(graph) else None,
    }
    if data.get("graph_properties") != actual_properties:
        errors.append(f"graph_properties mismatch: expected {actual_properties}")
    if data.get("official_challenge_kit_verified") is not False:
        errors.append("participant-defined model must not claim official authentication")
    return errors, data


def main():
    all_ok = True
    for name, (path, expected_qubits) in PROCESSORS.items():
        errors, data = validate(path, expected_qubits)
        if errors:
            all_ok = False
            print(f"FAIL: {name}: " + "; ".join(errors))
        else:
            print(f"PASS: {name}: {expected_qubits} qubits, {len(data['coupling_map'])} undirected edges")
    print("NOTICE: this validates participant-defined research models only; it is not hardware authentication.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
