from src.architecture_stress import run_architecture_stress_test, workload_circuits


def test_stress_suite_contains_distinct_connectivity_patterns():
    circuits = workload_circuits()
    assert set(circuits) == {"star", "chain", "ring"}
    assert circuits["star"].num_qubits == 3
    assert circuits["chain"].num_qubits == 4
    assert circuits["ring"].num_qubits == 5


def test_stress_suite_reports_both_processors_and_documented_metrics():
    results = run_architecture_stress_test()

    assert len(results) == 6
    assert set(results["workload"]) == {"star", "chain", "ring"}
    assert set(results["processor"]) == {"Processor A", "Processor B"}
    required = {
        "compiled_depth",
        "compiled_two_qubit_gates",
        "baseline_two_qubit_gates",
        "extra_two_qubit_gates",
        "measured_swap_instructions",
        "estimated_swap_equivalents",
        "physical_qubits_used",
        "seed",
        "interpretation",
    }
    assert required.issubset(results.columns)
    assert (results["compiled_depth"] >= 0).all()
    assert (results["compiled_two_qubit_gates"] >= 0).all()
    assert (results["physical_qubits_used"] > 0).all()
    assert results["interpretation"].str.contains("not a cryptographic attack estimate").all()
