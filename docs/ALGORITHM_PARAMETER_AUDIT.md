# Cryptographic algorithm and parameter-set audit

Audit snapshot: 2026-10-29. This is a code-maintenance reference, not a certification of an implementation, FIPS validation, or organizer submission compliance.

## Standards-backed parameter identifiers

| Family supported by the inventory classifier | Recognized identifiers / parameter values | Primary reference | Status note |
|---|---|---|---|
| ML-KEM (including legacy Kyber name aliases) | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | NIST FIPS 203 | Final standard; NIST has published a planning note about errata/potential updates. |
| ML-DSA (including legacy Dilithium aliases) | ML-DSA-44, ML-DSA-65, ML-DSA-87 | NIST FIPS 204 | Final standard; consult current errata. |
| SLH-DSA (including SPHINCS+ name aliases) | SHA2/SHAKE variants at 128s, 128f, 192s, 192f, 256s, 256f | NIST FIPS 205 | Final standard. The parameter-set family and variant must agree. |
| AES | 128-, 192-, and 256-bit keys | NIST FIPS 197 | Final standard. Key size is not the same as block size; AES block size is always 128 bits. |
| LMS / HSS and LM-OTS | RFC 8554-defined names and tuples | RFC 8554 | Hash-based signatures are stateful; inventory classification does not verify state management or implementation safety. |
| XMSS / XMSSMT | RFC 8391-defined names and tuples | RFC 8391 | Hash-based signatures are stateful; inventory classification does not verify state management or implementation safety. |
| FN-DSA / Falcon | 512 and 1024 family names recognized by the classifier | NIST PQC standardization status page | FIPS 206 remains in development in the cited NIST status material; do not describe it as a final FIPS standard. |
| HQC | HQC-128, HQC-192, HQC-256 family names recognized by the classifier | NIST selected-algorithms page | Selected for standardization; the cited NIST material says the final standard is forthcoming. Do not describe HQC as a final FIPS standard. |

## Source-of-truth links

- NIST FIPS 203, ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204, ML-DSA: https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205, SLH-DSA: https://csrc.nist.gov/pubs/fips/205/final
- NIST FIPS 197, AES: https://csrc.nist.gov/pubs/fips/197/final
- NIST PQC standardization status: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post_Quantum_Cryptography-Standardization
- NIST selected algorithms / HQC status: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms
- RFC 8554, LMS/HSS: https://www.rfc-editor.org/rfc/rfc8554.html
- RFC 8391, XMSS/XMSSMT: https://www.rfc-editor.org/rfc/rfc8391.html

## Important limitations and audit rules

1. A recognized algorithm family name is not proof that a deployed implementation is standards-conformant or cryptographically validated.
2. Missing parameter metadata is not treated as proof of invalidity; it remains an uncertainty for inventory review. Explicit malformed or conflicting values should become UNKNOWN.
3. Legacy aliases (Kyber, Dilithium, SPHINCS+, Falcon) may appear in older inventories. Keep the original input and document normalization; do not silently rewrite an asset's deployed identifier.
4. The current planner's parameter checks are inventory heuristics, not a complete parser for all encodings, OIDs, provider-specific names, protocol suites, or every optional RFC parameter combination. Records outside the explicitly supported forms should be routed to manual review rather than treated as validated.
5. NIST publications and their errata pages must be rechecked before a production release. Standards evolve; the code must not treat FN-DSA or HQC as final FIPS standards solely because their family names are recognized.
6. This audit does not substitute for the hackathon organizer's exact input/output schema, labeled dataset, or official evaluator. Those materials are still needed to claim exact submission compliance and official precision/recall.

## Reproducible checks

Run the unit tests:

    python -m pytest -q

Measure larger synthetic inventories (performance only, not accuracy):

    python scripts/benchmark_inventory.py --sizes 1000 10000 50000 --output results/inventory_scale_benchmark.json

Evaluate against a reviewed labeled dataset with columns asset_id,true_label:

    python scripts/evaluate_inventory.py --ground-truth data/raw/ground_truth.csv --predictions results/tables/crypto_inventory_predictions.csv --output results/inventory_metrics.json

Never report precision, recall, false-positive rates, or false-negative rates from synthetic labels or unreviewed candidates as real-world scanner quality.
