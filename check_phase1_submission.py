"""Check the online Phase 1 artifact set without certifying processor authenticity."""
from pathlib import Path
import json
import pandas as pd

ROOT = Path(__file__).parent


def main():
    required_files = [
        "main.ipynb", "report.md", "processors/processor_A.json", "processors/processor_B.json",
        "results/tables/AB_comparison.csv", "results/tables/final_comparison.csv",
        "results/figures/processor_A_graph.png", "results/figures/processor_B_graph.png",
        "results/figures/logical_vs_transpiled.png", "results/figures/AB_performance.png",
        "results/figures/architecture_tradeoffs.png",
    ]
    missing = [f for f in required_files if not (ROOT / f).exists()]
    if missing:
        print(f"FAIL: missing artifacts: {missing}")
        return 1
    for name, expected_qubits in [("processor_A.json", 5), ("processor_B.json", 9)]:
        data = json.loads((ROOT / "processors" / name).read_text())
        if data.get("num_qubits") != expected_qubits:
            print(f"FAIL: {name} expected {expected_qubits} qubits")
            return 1
    table = pd.read_csv(ROOT / "results/tables/AB_comparison.csv")
    required_metrics = {"success_probability", "depth", "two_qubit_gates", "swap_estimate", "physical_qubits_used", "runtime_seconds"}
    if not required_metrics.issubset(set(table["Metric"])):
        print(f"FAIL: missing required metrics: {sorted(required_metrics - set(table['Metric']))}")
        return 1
    print("PASS: online Phase 1 artifact checklist")
    print("NOTICE: processor graphs and noise are participant-defined research models; the guide does not provide an official processor JSON manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
