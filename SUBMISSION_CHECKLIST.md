# Phase 2 Submission Checklist

This checklist tracks the PS-P2 inventory CLI against the user-provided task requirements and the artifacts actually present in this repository. Passing local/CI tests does not imply organizer acceptance or official evaluation performance.

## Implemented in the repository

- [x] `run_inventory.py` accepts `--input` and `--output` CSV paths.
- [x] The CLI uses Python standard-library modules only; it does not import pandas or third-party packages.
- [x] Output columns and order are fixed: `asset_id,predicted_label,priority_score,priority_rank,recommended_action,migration_wave,depends_on,rationale`.
- [x] Exactly six labels are used: `QUANTUM_VULNERABLE`, `QUANTUM_RESISTANT`, `HYBRID`, `SYMMETRIC_OR_HASH`, `LEGACY_BROKEN`, and `UNKNOWN`.
- [x] RSA, DSA, DH/FFDHE, ECC/ECDH/ECDSA, and Ed/X25519 families are covered by regression tests.
- [x] ML-KEM, ML-DSA, SLH-DSA and supported additional PQC families are tested; classical + PQC combinations are classified as hybrid.
- [x] Ambiguous role/parameter combinations and unrecognized/missing algorithm values route to `UNKNOWN` where detectable.
- [x] Risk scoring follows the specified base/exposure/retention/criticality formula, caps at 100, and assigns deterministic ranks.
- [x] Migration waves use the exact strings `Wave 1`, `Wave 2`, `Wave 3`, and `review`.
- [x] Category-specific recommendations reference FIPS 203 ML-KEM for key establishment and FIPS 204 ML-DSA for signatures, with manual review for unknown roles.
- [x] Tests cover CLI execution, output schema/order, classification, parameter mismatches, dependencies, scoring, wave assignment, and a 1,000-row input.

## Blocked / not verifiable from this checkout

- [ ] Official `P2_inventory/inventory_dev.csv` and `P2_inventory/inventory_dev_labels.csv` are absent.
- [ ] Official `P2_inventory/baseline_classifier.py` and `P2_inventory/evaluate.py` are absent; Macro-F1, `unsafe_unknown_count`, and `hash_as_public_key_count` cannot be computed.
- [ ] `common/env_check.py`, its official environment contract, and `common/templates/report_template.md` are absent. Do not fabricate `platform_A_info.json` or official baseline/evaluation results.
- [ ] Official label conventions and evaluator-specific required columns cannot be confirmed without the organizer evaluator.
- [ ] Final `predictions.csv` and `results/inventory_eval_metrics.json` must be generated using the official labeled dataset/evaluator once supplied.
- [ ] Precision/recall for the public-repository scanner remain pending until a complete manual ground-truth audit has been reviewed.
- [ ] The current repository contains no `processors/processor_C.json`. Processor C/D scope differs between the available Phase 1 Master Guide and the event FAQ; confirm the team's current Phase 2 brief before inventing a C model or treating architecture artifacts as required.
- [ ] The Processor D model is a participant-defined 12-qubit simulation design, not an official hardware configuration.

## Evaluation results

Official evaluation: **not run**. The required labeled dataset and evaluator are absent. Synthetic samples and unit tests are not substitutes for the official score. See `docs/PHASE2_COMPLIANCE_AUDIT.md` for the source and scope notes.
