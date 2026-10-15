"""Measured metrics for identical A/B benchmark runs."""
import math
import time

from qiskit import transpile
from qiskit_aer import AerSimulator

from .processors import build_noise_model
from .routing import transpile_for_processor

SHOTS = 4096
SEED = 42


def _two_qubit_count(circuit):
    return sum(
        1
        for instruction in circuit.data
        if instruction.operation.name in {"cx", "cz", "ecr", "swap"}
        and len(instruction.qubits) == 2
    )


def _measured_swap_count(circuit):
    return sum(
        1
        for instruction in circuit.data
        if instruction.operation.name == "swap" and len(instruction.qubits) == 2
    )


def _physical_qubits_used(circuit):
    used = set()
    for instruction in circuit.data:
        used.update(circuit.find_bit(qubit).index for qubit in instruction.qubits)
    return len(used)


def _probability(counts, bitstring, shots):
    """Return the observed probability for a bitstring from a fixed-shot run."""
    if not isinstance(shots, int) or isinstance(shots, bool) or shots <= 0:
        raise ValueError("shots must be a positive integer")
    if not bitstring or any(bit not in "01" for bit in bitstring):
        raise ValueError("bitstring must contain only binary digits")
    successes = counts.get(bitstring, 0)
    if not isinstance(successes, int) or isinstance(successes, bool):
        raise ValueError("count for the selected bitstring must be an integer")
    if not 0 <= successes <= shots:
        raise ValueError("count for the selected bitstring must be between 0 and shots")
    return successes / shots


def _binomial_standard_error(probability, shots):
    """Estimate standard error for a binomial proportion from independent shots."""
    if not isinstance(shots, int) or isinstance(shots, bool) or shots <= 0:
        raise ValueError("shots must be a positive integer")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be between 0 and 1")
    return math.sqrt(probability * (1.0 - probability) / shots)


def run_processor_benchmark(logical_circuit, processor, marked="101"):
    start = time.perf_counter()
    compiled = transpile_for_processor(
        logical_circuit, processor, seed=SEED, optimization_level=1
    )
    simulator = AerSimulator(
        noise_model=build_noise_model(processor), seed_simulator=SEED
    )
    result = simulator.run(compiled, shots=SHOTS, seed_simulator=SEED).result()
    elapsed = time.perf_counter() - start
    counts = result.get_counts()
    probability = _probability(counts, marked, SHOTS)
    baseline = transpile(
        logical_circuit,
        basis_gates=processor["basis_gates"],
        coupling_map=None,
        optimization_level=1,
        seed_transpiler=SEED,
    )
    compiled_2q = _two_qubit_count(compiled)
    baseline_2q = _two_qubit_count(baseline)
    extra_2q = max(0, compiled_2q - baseline_2q)
    ideal_sim = AerSimulator(seed_simulator=SEED)
    ideal_result = ideal_sim.run(baseline, shots=SHOTS, seed_simulator=SEED).result()
    ideal_probability = _probability(ideal_result.get_counts(), marked, SHOTS)
    row = {
        "processor": processor["name"],
        "success_probability": probability,
        "std_error": _binomial_standard_error(probability, SHOTS),
        "depth": compiled.depth(),
        "two_qubit_gates": compiled_2q,
        "measured_swap_count": _measured_swap_count(compiled),
        # This is an estimated equivalent, not a direct count of SWAP instructions.
        "swap_estimate": extra_2q / 3,
        "physical_qubits_used": _physical_qubits_used(compiled),
        "total_ops": sum(compiled.count_ops().values()),
        "runtime_seconds": elapsed,
        "shots": SHOTS,
        "seed": SEED,
        "ideal_success_probability": ideal_probability,
        "baseline_two_qubit_gates": baseline_2q,
        "extra_two_qubit_gates": extra_2q,
    }
    return row, compiled, baseline


def compare_metrics(a, b):
    fields = [
        "success_probability",
        "std_error",
        "depth",
        "two_qubit_gates",
        "measured_swap_count",
        "swap_estimate",
        "physical_qubits_used",
        "total_ops",
        "runtime_seconds",
        "shots",
        "seed",
        "ideal_success_probability",
        "baseline_two_qubit_gates",
        "extra_two_qubit_gates",
    ]
    rows = []
    for field in fields:
        a_value, b_value = a[field], b[field]
        try:
            difference = b_value - a_value
        except TypeError:
            difference = ""
        rows.append(
            {
                "Metric": field,
                "Processor A": a_value,
                "Processor B": b_value,
                "Difference": difference,
            }
        )
    return rows
