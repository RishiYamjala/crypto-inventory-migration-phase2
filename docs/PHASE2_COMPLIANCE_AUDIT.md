# Phase 2 Compliance Audit — PS-P2 Inventory CLI

**Initial audit:** 2026-10-29  
**Status last checked:** 2026-10-30  
**Repository snapshot:** fixes described below are present on `main`; this document records code checks, not organizer acceptance.  
**Purpose:** distinguish code-level checks from official evaluation. This is not a claim of organizer acceptance.

## Code-level fixes merged into main

1. **Third-party dependency in the CLI.** The previous `run_inventory.py` imported pandas, contrary to the task requirement for an offline standard-library-only CLI. It now uses `argparse`, `csv`, `re`, `pathlib`, and other Python standard-library modules only. The inventory benchmark was updated to call the same CSV-based API.
2. **Scoring now uses the risk dimensions required by PS-P2.** The current patch preserves label bases (quantum-vulnerable 40; legacy-broken 35; unknown 20; hybrid 15; quantum-resistant/symmetric-or-hash 5) and explicitly adds internet exposure, data sensitivity, retention, and criticality. Unknown exposure, sensitivity, retention, and criticality receive documented nonzero allowances instead of being silently treated as low risk. The final score is capped at 100, and the rationale prints each component.
3. **Migration-wave schema.** The official `SCHEMA.md` requires exactly `1`, `2`, `3`, or `review`; display strings such as `Wave 1` are invalid. Unknown records are routed to `review`; a score of 75+ or an exposed quantum-vulnerable record is wave `1`; remaining quantum-vulnerable/legacy-broken records are wave `2`; other known categories are wave `3`.
4. **Tests depended on DataFrame-specific output.** CLI tests now use standard-library CSV records and validate the exact output schema and order.
5. **Processor D qubit count.** The repository's supplementary D model was previously 11 qubits. The event FAQ describes a custom 12-qubit D design, so the repository's participant-defined D model was updated to 12 qubits, 14 undirected edges, no triangles, and diameter 5. Its topology/noise/ports remain synthetic assumptions; it is not an official hardware config.

## Code-level checks now represented in tests

- Six allowed labels and conservative unknown handling.
- Classical public-key families: RSA, DSA, DH/FFDHE, ECC/ECDH/ECDSA, Ed25519 and X25519.
- PQC families and hybrid classical+PQC names.
- Role/algorithm contradictions and explicit parameter mismatches.
- Exact output schema, conservative alias/parameter handling, scoring components including sensitivity, score cap, stable rank, dependency evidence, and exact migration-wave values.
- CSV header aliases, duplicate/blank IDs, CLI execution, 1,000-row determinism, and Processor D graph/generator consistency.

## Official requirements still blocked

The repository tree reviewed did **not** contain:
- `P2_inventory/inventory_dev.csv`
- `P2_inventory/inventory_dev_labels.csv`
- `P2_inventory/baseline_classifier.py`
- `P2_inventory/evaluate.py`
- `common/env_check.py`
- `common/templates/report_template.md`

Therefore this repository cannot honestly produce the official Macro-F1, `unsafe_unknown_count`, `hash_as_public_key_count`, `platform_A_info.json`, or the required final official report yet. Those artifacts must come from the organizer; sample inventory predictions and synthetic unit tests must not be presented as official metrics.

The public-repository scanner can emit candidate findings and scan time, but its precision/recall remain **pending** until all candidate pairs are reviewed and missed true findings are manually added to the ground-truth file for the same repository and ref.

## Scope ambiguity: Processor C/D

The available **Phase 1 Master Guide V2** says Phase 1 requires only participant-defined Processors A and B, with C and custom D reserved for the offline finalist stage. The event FAQ describes a custom 12-qubit D and lists A/B/C/D among the deliverables. These sources do not fully settle what is required for this team's updated Phase 2 PS-P2 inventory task. The repository adjusts D to the 12-qubit design target but does not invent Processor C or claim that architecture deliverables satisfy the separate inventory task. Use the team's latest organizer-issued Phase 2 problem statement as the final authority.

## Source references reviewed

- Phase 1 Master Guide V2, available in the user's library and in `docs/`.
- Event FAQ: https://github.com/qiskitfallfest-srmap/QisKit-Fall-Fest-2026/blob/main/public/docs/faq.md
- Repository's `SUBMISSION_CHECKLIST.md`, `docs/PHASE1_COMPLIANCE.md`, `scripts/evaluate_public_repo.py`, `src/discovery.py`, and `run_inventory.py`.

## Final status

**Code-level fixes are merged into `main`.** After the merge commit `6166fc6d32c48166848b3923de4208a1e5c5583c`, the Python tests and project-validation workflow both completed successfully. This establishes repository-level checks only; official compliance and official scoring remain unverified until the organizer's exact Phase 2 brief, labeled dataset, and evaluator are available and used.


## Local smoke verification added (not official)

The checkout now contains:
- `examples/inventory_dev.csv` and `examples/inventory_dev_labels.csv`: a synthetic eleven-row regression fixture, separate from the organizer's official `P2_inventory/` dataset.
- `scripts/run_phase2_smoke_evaluation.py`: executes the local classifier, scores the hand-authored expected labels with `scripts/evaluate_inventory.py`, and compares it with an algorithm-name-only baseline.
- `scripts/crypto_library_selftest.py`: verifies that pinned library calls for ML-KEM-768, ML-DSA-65 and AES-256-GCM can complete a round trip. It does not implement cryptographic primitives itself.
- `scripts/capture_platform_info.py`: captures actual runtime and installed dependency metadata. CI stores its capture as an artifact.
- `platform_A_info.json`: a committed runtime snapshot of the GitHub Actions runner and installed pinned package versions. It is not the submitter's personal machine or official `common/env_check.py` output. Fresh runtime captures are uploaded by CI.

CI is configured to run these smoke checks and upload generated local outputs. They do not close the official-evaluation gap: the organizer's `P2_inventory/inventory_dev.csv`, labels, baseline classifier, evaluator, environment checker, README template, and report template are still required. No official Macro-F1 or related evaluator-specific metrics should be claimed from the synthetic fixture.
