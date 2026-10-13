# Phase 1 compliance record

Sources: [`QFF_IBM_Hackathon_Guideline.pdf`](QFF_IBM_Hackathon_Guideline.pdf), [`QFF_2026_Hackathon_Phase1_Participant_Instructions.pdf`](QFF_2026_Hackathon_Phase1_Participant_Instructions.pdf), and [`Challenge_Guide_Phase_1.pdf`](Challenge_Guide_Phase_1.pdf), downloaded from the shared organizer Drive folder supplied by the project owner.

| Guide requirement | Repository evidence | Status |
|---|---|---|
| Online Processor A and B comparison | `main.ipynb`, `results/tables/AB_comparison.csv` | Implemented provisionally |
| Processor A online stage | `processors/processor_A.json`, 5 qubits | Qubit count confirmed; exact edge list not present in PDF |
| Processor B online stage | `processors/processor_B.json`, 9 qubits | Latest organizer clarification; participant-defined edge list is documented |
| Same selected problem and controlled settings | `src/routing.py`, notebook controls | Implemented |
| Solution quality/reference comparison | `success_probability`, `ideal_success_probability` | Implemented |
| Circuit cost | `depth`, `two_qubit_gates`, `total_ops` | Implemented |
| Routing | `swap_estimate`, `extra_two_qubit_gates`, coupling graphs | Implemented; SWAP is explicitly an estimate |
| Qubit use | `physical_qubits_used` | Implemented |
| Noise/reproducibility | noise model, shots, seed, compiler settings | Implemented provisionally |
| A/B graphs and transpiled circuit | `results/figures/` | Implemented |
| Scientific interpretation | `report.md` | Implemented with limitations |
| Exact official Processor A/B definitions | `processors/challenge_kit_manifest.json` | Pending organizer-authenticated source; the Challenge Guide JSON is explicitly illustrative |
| Offline C/D Bell-correlation package | Not required for the online P2 target | Out of scope unless shortlisted |

## Important interpretation

The supplied PDFs establish the online stage, qubit counts, required measurements, and submission materials. The Challenge Guide's processor section provides an illustrative JSON structure and explicitly instructs participants to replace it with the exact organizer-supplied definition. It does **not** provide the real Processor A/B JSON definitions, complete coupling edge lists, basis gates, ports, compiler baseline, or numerical noise parameters. The repository therefore does not claim official A/B compliance. The manifest validator remains intentionally blocked until those values arrive from an authoritative organizer source.
