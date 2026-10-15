"""Grover construction and architecture-specific transpilation.

Processor JSON edges are interpreted as undirected couplings and expanded into
both directions for Qiskit. This is an explicit research-model assumption, not
a claim about official hardware directionality.
"""
from qiskit import QuantumCircuit, transpile


def build_grover_circuit(marked="101", iterations=2, measure=True):
    n = len(marked)
    if not marked or any(bit not in "01" for bit in marked):
        raise ValueError("marked must be a non-empty binary string")
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 0:
        raise ValueError("iterations must be a non-negative integer")
    qc = QuantumCircuit(n, n if measure else 0)
    qc.h(range(n))
    for _ in range(iterations):
        for q, bit in enumerate(reversed(marked)):
            if bit == "0":
                qc.x(q)
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)
        for q, bit in enumerate(reversed(marked)):
            if bit == "0":
                qc.x(q)
        qc.h(range(n))
        qc.x(range(n))
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)
        qc.x(range(n))
        qc.h(range(n))
    if measure:
        qc.measure(range(n), range(n))
    return qc


def bidirectional_coupling_map(processor):
    """Return sorted unique directed edges from undirected JSON couplings."""
    n = processor["num_qubits"]
    directed = set()
    for edge in processor["coupling_map"]:
        if len(edge) != 2:
            raise ValueError(f"Invalid coupling edge: {edge!r}")
        a, b = edge
        if not isinstance(a, int) or not isinstance(b, int) or a == b:
            raise ValueError(f"Invalid coupling edge: {edge!r}")
        if min(a, b) < 0 or max(a, b) >= n:
            raise ValueError(f"Coupling edge outside {n}-qubit device: {edge!r}")
        directed.add((a, b))
        directed.add((b, a))
    return [list(edge) for edge in sorted(directed)]


def transpile_for_processor(circuit, processor, seed=42, optimization_level=1):
    return transpile(
        circuit,
        basis_gates=processor["basis_gates"],
        coupling_map=bidirectional_coupling_map(processor),
        optimization_level=optimization_level,
        seed_transpiler=seed,
    )
