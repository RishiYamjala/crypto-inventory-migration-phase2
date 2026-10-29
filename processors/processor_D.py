"""Generate the supplementary participant-defined Processor D configuration."""
from pathlib import Path
import json

CONFIG = {
  "name": "Processor D",
  "num_qubits": 12,
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
      8,
      9
    ],
    [
      9,
      10
    ],
    [
      1,
      4
    ],
    [
      4,
      7
    ],
    [
      7,
      10
    ],
    [
      10,
      11
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
  "topology_description": "Twelve-qubit sparse chain-with-chords research architecture with 14 undirected edges, no triangles, and graph diameter 5. Three long-range chords shorten selected routes while retaining sparse connectivity.",
  "stage": "Supplementary participant-defined research model D (12-qubit design target)",
  "source": "Participant-designed topology for exploratory simulation; not an organizer-issued processor configuration",
  "official_challenge_kit_verified": False,
  "note": "Synthetic research model only. Qubit count, coupling map, ports, and noise values are explicit assumptions for reproducible simulation; they are not official hardware specifications or calibrated measurements.",
  "graph_properties": {
    "undirected_edge_count": 14,
    "triangle_count": 0,
    "diameter": 5
  }
}

def build_processor():
    """Return a detached copy of the Processor D simulation configuration."""
    return json.loads(json.dumps(CONFIG))

def write_processor(path=None):
    path = Path(path or Path(__file__).with_name("processor_D.json"))
    path.write_text(json.dumps(build_processor(), indent=2) + "\n", encoding="utf-8")
    return path

if __name__ == "__main__":
    print(write_processor())
