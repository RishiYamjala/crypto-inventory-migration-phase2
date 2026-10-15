"""Generate the participant-defined Phase 1 Processor B configuration.

The nine-qubit graph is a heavy-hex-inspired participant design based on the
organizer reference architecture. It is not presented as an official edge
list; the graph and simulator assumptions are part of this submission's
architecture experiment.
"""
from pathlib import Path
import json

CONFIG = {
    "name": "Processor B",
    "num_qubits": 9,
    "coupling_map": [
        [0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6],
        [1, 4], [2, 5], [1, 7], [2, 8],
    ],
    "basis_gates": ["rz", "sx", "x", "cx"],
    "ports": {"readout": "standard", "control": "standard"},
    "noise": {
        "one_qubit_depolarizing": 0.001,
        "cx_depolarizing": 0.005,
        "readout_error": 0.01,
    },
    "topology_description": (
        "Nine-qubit heavy-hex-inspired participant reference architecture; "
        "node labels and edge directions are participant-defined for this "
        "reproducible research simulation."
    ),
    "stage": "Phase 1 online Processor B",
    "source": "organizer reference image and chat clarification; participant-defined research simulation",
    "official_challenge_kit_verified": False,
    "note": (
        "PARTICIPANT-DEFINED RESEARCH MODEL - exact official basis gates, ports, "
        "directionality, and noise values are not supplied"
    ),
}


def build_processor():
    return json.loads(json.dumps(CONFIG))


def write_processor(path=None):
    path = Path(path or Path(__file__).with_name("processor_B.json"))
    path.write_text(json.dumps(build_processor(), indent=2) + "\n", encoding="utf-8")
    return path


if __name__ == "__main__":
    print(write_processor())
