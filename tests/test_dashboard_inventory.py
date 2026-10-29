import csv
import io

import pytest

from run_inventory import OUTPUT_COLUMNS
from src.dashboard_inventory import (
    predict_inventory_csv_bytes,
    serialize_predictions_csv,
)


DEMO_CSV = (
    "asset_id,algorithm,primitive,internet_exposed,data_retention_years,criticality,depends_on\n"
    "tls-cert,RSA-2048,digital_signature,yes,10,critical,api\n"
    "pqc-kem,ML-KEM-768,key_establishment,no,5,high,\n"
    "database,AES-256-GCM,symmetric_encryption,no,10,critical,\n"
    "vendor-key,Vendor-Managed,unknown,unknown,,medium,\n"
).encode("utf-8")


def test_dashboard_upload_runs_phase2_classifier_and_preserves_contract():
    predictions = predict_inventory_csv_bytes(DEMO_CSV)

    assert [row["predicted_label"] for row in predictions] == [
        "QUANTUM_VULNERABLE",
        "QUANTUM_RESISTANT",
        "SYMMETRIC_OR_HASH",
        "UNKNOWN",
    ]
    assert all(list(row) == OUTPUT_COLUMNS for row in predictions)
    assert predictions[0]["migration_wave"] == "Wave 1"
    assert predictions[3]["migration_wave"] == "review"


def test_dashboard_download_is_exact_eight_column_csv():
    predictions = predict_inventory_csv_bytes(DEMO_CSV)
    rendered = serialize_predictions_csv(predictions)
    reader = csv.DictReader(io.StringIO(rendered, newline=""))

    assert reader.fieldnames == OUTPUT_COLUMNS
    rows = list(reader)
    assert len(rows) == 4
    assert rows[0]["asset_id"] == "tls-cert"
    assert rows[3]["predicted_label"] == "UNKNOWN"


@pytest.mark.parametrize("payload", [b"", b"not_an_inventory_header\nvalue\n"])
def test_dashboard_rejects_empty_or_invalid_uploads(payload):
    with pytest.raises(ValueError):
        predict_inventory_csv_bytes(payload)



def test_shipped_phase2_demo_exercises_all_six_labels():
    demo_path = __import__("pathlib").Path(__file__).resolve().parents[1] / "examples" / "phase2_inventory_demo.csv"
    predictions = predict_inventory_csv_bytes(demo_path.read_bytes())
    labels = {row["predicted_label"] for row in predictions}

    assert labels == {
        "QUANTUM_VULNERABLE",
        "QUANTUM_RESISTANT",
        "HYBRID",
        "SYMMETRIC_OR_HASH",
        "LEGACY_BROKEN",
        "UNKNOWN",
    }
    assert len(predictions) == 9
    assert all(list(row) == OUTPUT_COLUMNS for row in predictions)
