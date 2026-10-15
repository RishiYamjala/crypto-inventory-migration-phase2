# Processor configuration status

## What the guide provides

Master Guide V2 defines the Phase 1 benchmark requirements, including the five-qubit Processor A, nine-qubit Processor B, basis gates `rz/sx/x/cx`, and simulator noise settings used by this repository. It does not provide official Processor A/B JSON files or a downloadable authoritative processor manifest. Participants are expected to define and justify valid coupling maps.

## Participant-defined research models

- **Processor A:** five-qubit branching tree with 4 undirected edges, 0 triangles, and diameter 3.
- **Processor B:** nine-qubit connected graph with 12 undirected edges, 2 triangles (nodes 3-4-5 and 6-7-8), and diameter 4. This gives an explicit, testable rationale for local connectivity and path lengths.
- **Basis gates:** `rz`, `sx`, `x`, `cx`.
- **Noise assumptions:** one-qubit depolarizing 0.001, CX depolarizing 0.005, readout error 0.01.
- **Coupling semantics:** JSON edges are treated as undirected physical couplings and expanded in both directions for Qiskit transpilation.

These are reproducible participant choices. The models are not presented as official hardware calibration files. The `validate_processors.py` script checks internal structure and guide settings only; it does not authenticate real hardware.

## Evidence and next verification

After changing the coupling map, rerun the notebook and supplementary stress tests, then inspect the newly generated tables and figures. Do not reuse benchmark numbers produced by an older topology. See `docs/PHASE1_COMPLIANCE.md` for the guide requirement map.
