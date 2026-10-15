"""Supplementary, non-required circuits for comparing processor topology costs.

These small synthetic workloads complement (and never replace) the required common
Grover benchmark. Results are simulator/compiler metrics for participant-defined
processor models, not real-hardware performance or cryptographic attack estimates.
Run from the repository root with: python -m src.architecture_stress
"""
from pathlib import Path

import pandas as pd
from qiskit import QuantumCircuit, transpile

from .metrics import (
    _measured_swap_count,
    _physical_qubits_used,
    _two_qubit_count,
)
from .processors import load_processor
from .routing import transpile_for_processor

SEED = 42


def workload_circuits():
    """Return a stable set of circuits that exercise different connectivity patterns."""
    star = QuantumCircuit(3, name="star")
    star.cx(0, 1)
    star.cx(0, 2)
    star.cx(0, 1)
    star.cx(0, 2)

    chain = QuantumCircuit(4, name="chain")
    chain.cx(0, 1)
    chain.cx(1, 2)
    chain.cx(2, 3)
    chain.cx(0, 3)
    chain.cx(1, 3)

    # Five-qubit cycle: Processor B contains the 0-4 closing edge,
    # while Processor A is a tree and must route at least one cycle interaction.
    # This makes the topology comparison exercise a real structural difference.
    ring = QuantumCircuit(5, name="ring")
    ring.cx(0, 1)
    ring.cx(1, 2)
    ring.cx(2, 3)
    ring.cx(3, 4)
    ring.cx(4, 0)
    ring.cx(0, 2)
    ring.cx(1, 3)

    return {"star": star, "chain": chain, "ring": ring}


def run_architecture_stress_test(processor_a_path="processors/processor_A.json",
                                 processor_b_path="processors/processor_B.json"):
    """Compile the same supplementary workloads against both processor maps."""
    processors = [
        load_processor(processor_a_path),
        load_processor(processor_b_path),
    ]
    rows = []
    for workload_name, circuit in workload_circuits().items():
        for processor in processors:
            compiled = transpile_for_processor(
                circuit, processor, seed=SEED, optimization_level=1
            )
            baseline = transpile(
                circuit,
                basis_gates=processor["basis_gates"],
                coupling_map=None,
                seed_transpiler=SEED,
                optimization_level=1,
            )
            baseline_two_qubit = _two_qubit_count(baseline)
            compiled_two_qubit = _two_qubit_count(compiled)
            extra_two_qubit = max(0, compiled_two_qubit - baseline_two_qubit)
            rows.append({
                "workload": workload_name,
                "processor": processor["name"],
                "logical_qubits": circuit.num_qubits,
                "compiled_depth": compiled.depth(),
                "compiled_two_qubit_gates": compiled_two_qubit,
                "baseline_two_qubit_gates": baseline_two_qubit,
                "extra_two_qubit_gates": extra_two_qubit,
                "measured_swap_instructions": _measured_swap_count(compiled),
                "estimated_swap_equivalents": extra_two_qubit / 3,
                "physical_qubits_used": _physical_qubits_used(compiled),
                "seed": SEED,
                "interpretation": "supplementary compiler stress test; not a cryptographic attack estimate",
            })
    return pd.DataFrame(rows)


def main():
    output = Path("results/tables/architecture_stress_test.csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    results = run_architecture_stress_test()
    results.to_csv(output, index=False)
    print(results.to_string(index=False))
    print(f"\nSaved supplementary results to {output}")


if __name__ == "__main__":
    main()
