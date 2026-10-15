"""Generate the participant-defined Phase 1 Processor B configuration."""
from pathlib import Path
import json

CONFIG = {
  "name": "Processor B",
  "num_qubits": 9,
  "coupling_map": [
    [
      0,
      1
    ],
    [
      1,
      2
    ],
    [
      2,
      3
    ],
    [
      3,
      4
    ],
    [
      4,
      5
    ],
    [
      5,
      6
    ],
    [
      6,
      7
    ],
    [
      7,
      8
    ],
    [
      3,
      5
    ],
    [
      6,
      8
    ],
    [
      0,
      4
    ],
    [
      2,
      6
    ]
  ],
  "basis_gates": [
    "rz",
    "sx",
    "x",
    "cx"
  ],
  "ports": {
    "readout": "standard",
    "control": "standard"
  },
  "noise": {
    "one_qubit_depolarizing": 0.001,
    "cx_depolarizing": 0.005,
    "readout_error": 0.01
  },
  "topology_description": "Nine-qubit connected research graph with 12 undirected edges, two triangles (3-4-5 and 6-7-8), and graph diameter 4. The two local triangles provide explicit dense three-node neighborhoods, while the added chords reduce long-range path lengths.",
  "stage": "Phase 1 online Processor B",
  "source": "participant-designed topology guided by the organizer's nine-qubit requirement; research simulation",
  "graph_properties": {
    "undirected_edge_count": 12,
    "triangle_count": 2,
    "diameter": 4
  },
  "official_challenge_kit_verified": False,
  "note": "Participant-defined research model. This graph is intentionally designed for the experiment and is not represented as an organizer-issued edge list or calibrated hardware."
}

def build_processor():
    return json.loads(json.dumps(CONFIG))

def write_processor(path=None):
    path = Path(path or Path(__file__).with_name("processor_B.json"))
    path.write_text(json.dumps(build_processor(), indent=2) + "\n", encoding="utf-8")
    return path

if __name__ == "__main__":
    print(write_processor())
