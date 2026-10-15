# Phase 1 compliance record

Sources reviewed: the Master Guide V2 and the available participant instructions and Challenge Guide PDFs in this repository's `docs/` directory.

| Guide requirement | Repository evidence | Status |
|---|---|---|
| P2 cryptographic scanner targets RSA, DSA, DH, and ECC | `src/discovery.py` | Implemented as static candidate detection; requires manual evaluation |
| FIPS 203/204 migration reference | Scanner `fips_migration` column and migration planner | Implemented with role-review caveats |
| Public-repository evaluation with precision, recall, and scan time | `scripts/evaluate_public_repo.py` | Runner implemented; valid metrics require a completed manual ground-truth audit |
| Processor A/B qubit counts | `processors/processor_A.json`, `processors/processor_B.json` | 5 and 9 qubits |
| Basis gates and simulator noise | Processor JSON files and `src/processors.py` | Matches guide settings: rz/sx/x/cx; one-qubit 0.001, CX 0.005, readout 0.01 |
| Coupling-map rationale | Processor JSON descriptions and report | Participant-defined graphs documented; A has 4 edges/diameter 3, B has 12 edges/2 triangles/diameter 4 |
| Same circuit and controlled A/B settings | `main.ipynb`, `src/metrics.py` | Implemented; regenerate outputs after topology changes |
| Quantitative A/B table and graph figures | `results/tables/`, `results/figures/` | Committed snapshot exists; regenerate and inspect CI artifacts after code changes before final submission |
| Pinned dependencies | `requirements.txt` | Pinned for Python 3.12; CI must confirm compatibility |
| Required processed-data tree | `data/processed/` | Included |
| Official processor JSON provenance | Master Guide V2 | The guide intentionally does not provide official processor JSON files; local models are explicitly participant-defined, not marked as official |

## Interpretation and limitations

The processor graphs are research models chosen to satisfy the stated 5-qubit and 9-qubit counts and to make topology properties explicit. Processor B is a connected 12-edge graph with two triangles. The basis gates and noise settings follow the guide's benchmark requirements, but simulator noise values are not claims about measured hardware calibration.

The scanner is regex-based candidate discovery, not a complete parser or vulnerability scanner. Precision and recall must not be reported until a public repository has been scanned and a complete, manually reviewed ground-truth set has been scored. The benchmark outputs must be regenerated after any change to processor topology or transpilation assumptions. CI uploads regenerated artifacts for inspection; committed CSVs are snapshots and are not automatically pushed back by CI.
