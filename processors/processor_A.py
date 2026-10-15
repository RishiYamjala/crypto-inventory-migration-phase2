"""Generate the participant-defined Phase 1 Processor A configuration."""
from pathlib import Path
import json

CONFIG = {
  "name": "Processor A",
  "num_qubits": 5,
  "coupling_map": [
    [
      0,
      1
    ],
    [
      0,
      2
    ],
    [
      0,
      3
    ],
    [
      3,
      4
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
  "topology_description": "Five-qubit branching-tree research architecture with 4 undirected edges, no triangles, and graph diameter 3. It has a three-edge longest shortest path and limited connectivity.",
  "stage": "Phase 1 online Processor A",
  "source": "participant-defined topology based on the organizer reference image; research simulation",
  "graph_properties": {
    "undirected_edge_count": 4,
    "triangle_count": 0,
    "diameter": 3
  },
  "official_challenge_kit_verified": False,
  "note": "Participant-defined research model. Exact official ports and hardware calibration data are not supplied; the topology and noise are explicit simulation assumptions."
}

def build_processor():
    return json.loads(json.dumps(CONFIG))

def write_processor(path=None):
    path = Path(path or Path(__file__).with_name("processor_A.json"))
    path.write_text(json.dumps(build_processor(), indent=2) + "\n", encoding="utf-8")
    return path

if __name__ == "__main__":
    print(write_processor())
