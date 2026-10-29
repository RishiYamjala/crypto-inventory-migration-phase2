"""Reproducible synthetic scale benchmark for the inventory planner.

Reports wall time, throughput, and Python-traced peak allocations. The latter
is not total process RSS and can undercount memory allocated by native libraries.
"""
from __future__ import annotations

import argparse
import json
import tempfile
import time
import tracemalloc
from pathlib import Path

import pandas as pd

from run_inventory import build_predictions, validate_predictions

ALGORITHMS = (
    ("RSA-2048", "key establishment"),
    ("ML-KEM-768", "key establishment"),
    ("AES-256-GCM", "symmetric encryption"),
    ("DES-CBC", "symmetric encryption"),
    ("SHA-256", "hash"),
    ("ML-DSA-65", "digital signature"),
    ("vendor-managed", "unknown"),
)


def make_inventory(size: int) -> pd.DataFrame:
    rows = []
    for i in range(size):
        algorithm, role = ALGORITHMS[i % len(ALGORITHMS)]
        rows.append({
            "asset_id": f"benchmark-{i:08d}",
            "algorithm": algorithm,
            "primitive": role,
            "internet_exposed": ("yes", "no", "unknown")[i % 3],
            "data_retention_years": (1, 5, 10, "permanent")[i % 4],
            "criticality": ("low", "medium", "high", "critical")[i % 4],
            "data_sensitivity": ("public", "internal", "confidential", "restricted")[i % 4],
        })
    return pd.DataFrame(rows)


def run_benchmark(sizes: list[int]) -> list[dict]:
    if not sizes or any(size < 1 for size in sizes):
        raise ValueError("All benchmark sizes must be positive integers")
    results = []
    with tempfile.TemporaryDirectory(prefix="inventory-benchmark-") as temp:
        root = Path(temp)
        for size in sizes:
            input_path = root / f"inventory-{size}.csv"
            make_inventory(size).to_csv(input_path, index=False)
            tracemalloc.start()
            started = time.perf_counter()
            predictions = build_predictions(input_path)
            elapsed = time.perf_counter() - started
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            validate_predictions(predictions, input_path)
            if len(predictions) != size:
                raise AssertionError(f"Expected {size} rows, got {len(predictions)}")
            results.append({
                "rows": size,
                "wall_seconds": round(elapsed, 6),
                "rows_per_second": round(size / elapsed, 2) if elapsed else None,
                "python_traced_peak_bytes": peak_bytes,
                "output_rows": len(predictions),
                "validation": "passed",
            })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes", nargs="+", type=int, default=[1000, 10000, 50000],
        help="Inventory sizes to test (default: 1000 10000 50000)",
    )
    parser.add_argument("--output", help="Optional JSON output path")
    args = parser.parse_args()
    report = {
        "benchmark": "synthetic inventory classification",
        "notes": [
            "Synthetic records are for performance only, not classification-quality evaluation.",
            "Runtime depends on hardware and environment; compare runs on the same machine.",
            "python_traced_peak_bytes is not total process RSS and may omit native allocations.",
        ],
        "results": run_benchmark(args.sizes),
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
