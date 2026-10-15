from pathlib import Path

import validate_processors


def test_participant_processor_models_pass_structural_validation():
    for path, expected_qubits in validate_processors.PROCESSORS.values():
        errors, data = validate_processors.validate(path, expected_qubits)
        assert errors == []
        assert data["official_challenge_kit_verified"] is False


def test_validator_rejects_wrong_qubit_count():
    path = Path("processors/processor_A.json")
    errors, _ = validate_processors.validate(path, expected_qubits=9)
    assert any("expected 9 qubits" in error for error in errors)
