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
- [x] Risk scoring explicitly uses label risk, internet exposure, data sensitivity, retention, and criticality; missing metadata gets a conservative nonzero allowance, scores are capped at 100, and ranks are deterministic.
- [x] Migration-wave values match the official schema exactly: `1`, `2`, `3`, or `review`.
- [x] Category-specific recommendations reference FIPS 203 ML-KEM for key establishment and FIPS 204 ML-DSA for signatures, with manual review for unknown roles.
- [x] Tests cover CLI execution, output schema/order, classification, parameter mismatches, dependencies, scoring, wave assignment, and a 1,000-row input.
- [x] Added a local `examples/inventory_dev.csv` smoke fixture with explicit expected labels; clearly distinguished from the organizer's missing dataset.
- [x] Added a repeatable algorithm-only baseline comparison and local metrics generator. Outputs are marked local/synthetic, not official results.
- [x] Added `cryptography==50.0.2`, `pqcrypto==1.0.0`, and `psutil>=5.9` per the supplied kit, with runtime smoke tests for library-backed AES-GCM, ML-KEM-768, and ML-DSA-65 operations.
- [x] Added `platform_A_info.json` as a runtime-captured GitHub Actions runner snapshot plus a portable capture script. It is not the submitter's machine or official checker output.

## Blocked / not verifiable from this checkout

- [ ] Official `P2_inventory/inventory_dev.csv` and `P2_inventory/inventory_dev_labels.csv` are absent. The committed `examples/inventory_dev.csv` is a synthetic smoke fixture and is not a substitute.
- [ ] Official `P2_inventory/baseline_classifier.py` and `P2_inventory/evaluate.py` are absent; official Macro-F1, `unsafe_unknown_count`, and `hash_as_public_key_count` cannot be computed. The local algorithm-only baseline comparison is regression evidence only.
- [ ] `common/env_check.py`, its official environment contract, `common/templates/README_template.md`, and `common/templates/report_template.md` are absent. `platform_A_info.json` is an honest declared profile, not official checker output; exact README/report-template compliance remains unverified.
- [ ] Official label conventions and evaluator-specific required columns cannot be confirmed without the organizer evaluator.
- [ ] Final official `predictions.csv` and `results/inventory_eval_metrics.json` must be regenerated using the official labeled dataset/evaluator once supplied. The similarly named local smoke report is explicitly not an official score.
- [ ] Precision/recall for the public-repository scanner remain pending until a complete manual ground-truth audit has been reviewed.
- [ ] The current repository contains no `processors/processor_C.json`. Processor C/D scope differs between the available Phase 1 Master Guide and the event FAQ; confirm the team's current Phase 2 brief before inventing a C model or treating architecture artifacts as required.
- [ ] The Processor D model is a participant-defined 12-qubit simulation design, not an official hardware configuration.

## Evaluation results

Official evaluation: **not run**. The required labeled dataset, baseline, evaluator, environment checker, and exact templates are absent. The repo now has a separate synthetic smoke-test output and baseline comparison, but those are not substitutes for the official score. See `docs/PHASE2_COMPLIANCE_AUDIT.md` for the source and scope notes.


## Added local verification (not official)

The workflow now:
1. Runs the eight-column CLI against `examples/inventory_dev.csv`.
2. Generates `results/inventory_eval_metrics.json` and `results/tables/inventory_baseline_comparison.json` on that synthetic fixture, comparing the main classifier to an algorithm-name-only baseline.
3. Performs library-backed AES-GCM, ML-KEM-768, and ML-DSA-65 round trips using pinned `cryptography` and `pqcrypto` packages.
4. Captures actual CI host/package metadata into `platform_A_info.ci.json` as a workflow artifact.

The committed `platform_A_info.json` records the validated GitHub Actions runner and pinned package versions; a fresh capture is available in the CI artifact. Tracked smoke predictions and metrics are committed, but their labels remain synthetic. The official environment check and evaluator remain blocked until organizers provide their files.
