"""Pure helpers for running the Phase 2 inventory CLI from the Streamlit dashboard."""
from __future__ import annotations

import csv
import io
import tempfile
from pathlib import Path
from typing import Any, Sequence

from run_inventory import OUTPUT_COLUMNS, build_predictions, validate_predictions


def predict_inventory_csv_bytes(payload: bytes | bytearray) -> list[dict[str, Any]]:
    """Validate and classify a user-uploaded CSV without persisting it after the call."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("CSV upload must be bytes")
    if not payload:
        raise ValueError("Uploaded CSV is empty")

    with tempfile.TemporaryDirectory(prefix="inventory-dashboard-") as directory:
        input_path = Path(directory) / "uploaded_inventory.csv"
        input_path.write_bytes(payload)
        predictions = build_predictions(input_path)
        validate_predictions(predictions, input_path)

    # Return only the contractual output schema, in its required order.
    return [{column: row[column] for column in OUTPUT_COLUMNS} for row in predictions]


def serialize_predictions_csv(predictions: Sequence[dict[str, Any]]) -> str:
    """Serialize validated predictions using the exact eight-column CLI contract."""
    rows = list(predictions)
    validate_predictions(rows)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()
