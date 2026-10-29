# Phase 2 Submission Checklist

This checklist tracks the requested PS-P2 inventory deliverables against the files available in this repository. It does not imply organizer acceptance or measured evaluation performance.

## Implemented in this repository

- [x] `run_inventory.py` accepts `--input` and `--output` CSV paths.
- [x] Classifies supported algorithm families into six labels and defaults blank or unrecognized strings to `UNKNOWN`.
- [x] Produces `asset_id`, `predicted_label`, `priority_score`, `priority_rank`, `recommended_action`, `migration_wave`, `depends_on`, and `rationale`.
- [x] Includes tests for representative algorithms, hybrid patterns, unknown handling, scores, and ranks.
- [x] Includes DSA and DH regression cases in the algorithm-family tests.
- [ ] Run the full test suite in the submission environment after installing `requirements.txt`.

## Blocked / not verifiable from this checkout

- [ ] Official `P2_inventory/inventory_dev.csv` and `P2_inventory/inventory_dev_labels.csv` are not present.
- [ ] `P2_inventory/baseline_classifier.py` and `P2_inventory/evaluate.py` are not present; Macro-F1, `unsafe_unknown_count`, and `hash_as_public_key_count` cannot be computed here.
- [ ] `common/env_check.py`, its official environment contract, and `common/templates/report_template.md` are not present. Do not fabricate `platform_A_info.json` or official baseline/evaluation results.
- [ ] Official label conventions and evaluator-specific required columns should be confirmed against the organizer-provided evaluator.
- [ ] Generate final `predictions.csv` and `results/inventory_eval_metrics.json` using the official labeled dataset and evaluator, then record actual metrics.
- [ ] Complete the final report against the organizer template once provided.

## Evaluation results

Not run: the required labeled dataset and evaluator are absent from this repository checkout. The sample in `examples/predictions_demo.csv` is illustrative only. No Macro-F1 claim is made.
