"""Generate the participant-defined Phase 1 Processor A configuration.

The five-qubit branching graph follows the organizer-provided reference image.
Its basis gates, ports, and noise values are explicit simulator assumptions,
not official Challenge Kit parameters.
"""
from pathlib import Path
import json

CONFIG = {
    "name": "Processor A",
    "num_qubits": 5,
    "coupling_map": [[0, 1], [0, 2], [0, 3], [3, 4]],
    "basis_gates": ["rz", "sx", "x", "cx"],
    "ports": {"readout": "standard", "control": "standard"},
    "noise": {
        "one_qubit_depolarizing": 0.001,
        "cx_depolarizing": 0.005,
        "readout_error": 0.01,
    },
    "topology_description": (
        "Five-qubit branching-tree reference architecture transcribed from the "
        "supplied processor image; node labels are participant-assigned."
    ),
    "stage": "Phase 1 online Processor A",
    "source": "organizer reference image; participant-defined research simulation",
    "official_challenge_kit_verified": False,
    "note": (
        "PARTICIPANT-DEFINED RESEARCH MODEL - exact official basis gates, ports, "
        "directionality, and noise values are not supplied"
    ),
}


def build_processor():
    return json.loads(json.dumps(CONFIG))


def write_processor(path=None):
    path = Path(path or Path(__file__).with_name("processor_A.json"))
    path.write_text(json.dumps(build_processor(), indent=2) + "\n", encoding="utf-8")
    return path


if __name__ == "__main__":
    print(write_processor())
