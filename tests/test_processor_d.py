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


def test_three_processor_comparison_includes_d_and_deltas():
    from src.metrics import compare_three_metrics

    base = {
        "success_probability": 0.5,
        "std_error": 0.01,
        "depth": 10,
        "two_qubit_gates": 8,
        "measured_swap_count": 0,
        "swap_estimate": 1.0,
        "physical_qubits_used": 3,
        "total_ops": 20,
        "runtime_seconds": 0.1,
        "shots": 4096,
        "seed": 42,
        "ideal_success_probability": 0.9,
        "baseline_two_qubit_gates": 5,
        "extra_two_qubit_gates": 3,
    }
    a = {**base, "processor": "Processor A"}
    b = {**base, "processor": "Processor B", "success_probability": 0.7}
    d = {**base, "processor": "Processor D", "success_probability": 0.6}
    rows = compare_three_metrics(a, b, d)
    success_row = next(row for row in rows if row["Metric"] == "success_probability")
    assert list(success_row) == ["Metric", "Processor A", "Processor B", "Processor D", "B - A", "D - A", "D - B"]
    assert abs(success_row["D - A"] - 0.1) < 1e-12
    assert abs(success_row["D - B"] + 0.1) < 1e-12


def test_processor_d_metric_snapshot_and_three_way_comparison_are_committed():
    import csv

    with (ROOT / "results" / "tables" / "processor_D_metrics.csv").open(
        newline="", encoding="utf-8"
    ) as stream:
        d_rows = list(csv.DictReader(stream))
    assert len(d_rows) == 1
    assert d_rows[0]["processor"] == "Processor D"
    assert int(d_rows[0]["shots"]) == 4096
    assert int(d_rows[0]["seed"]) == 42

    with (ROOT / "results" / "tables" / "ABD_comparison.csv").open(
        newline="", encoding="utf-8"
    ) as stream:
        comparison = {row["Metric"]: row for row in csv.DictReader(stream)}
    assert comparison["success_probability"]["Processor D"] == "0.74169921875"
    assert comparison["depth"]["Processor D"] == "87.0"
    assert comparison["two_qubit_gates"]["Processor D"] == "48.0"
