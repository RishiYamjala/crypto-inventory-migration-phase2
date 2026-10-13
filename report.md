# P2 Report — Crypto Inventory & Migration Planner

## What changed?
The inventory was scored with the specified lookup tables, and each asset received a migration recommendation and phase. The same marked-state Grover circuit was compiled and executed on both participant-defined research processor models. The latest organizer clarification defines Processor A as 5 qubits and Processor B as 9 qubits; coupling maps are participant-designed reference architectures, while exact official basis gates, ports, directionality, and noise values remain unspecified.

## Which architectural property changed?
Processor A uses coupling edges [[0, 1], [0, 2], [0, 3], [3, 4]]; Processor B uses coupling edges [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [1, 4], [2, 5], [1, 7], [2, 8]]. The participant-selected basis gates and illustrative simulator noise parameters were held constant for this controlled comparison; they are not official calibration values.

## Did transpilation add routing?
Using the all-to-all baseline, Processor A compiled to 45 counted two-qubit gates versus 24 baseline, for an estimated SWAP overhead of 7.000000; explicit measured SWAP instructions were 0. Processor B compiled to 45 versus 24 baseline, for an estimated SWAP overhead of 7.000000; explicit measured SWAP instructions were 0. This distinguishes direct SWAP instructions from the estimate extra two-qubit gates divided by three.

## How many extra operations?
The total compiled operation counts were 276 for Processor A and 276 for Processor B; extra two-qubit counts versus baseline were 21 and 21.

## Did the problem metric change?
For this three-qubit Grover circuit, the fixed seed and optimizer selected equivalent routing metrics on the two research graphs; that is a legitimate result for this workload, not evidence that the graphs are identical. A topology-sensitive regression circuit is tested separately. The measured success probabilities for state `101` were 0.583496 ± 0.010893 for Processor A and 0.583496 ± 0.010893 for Processor B. The difference (B − A) was 0.000000. Ideal reference probabilities were 0.952637 and 0.952637.

## Could gate-set/noise differences also contribute?
Yes. This run keeps basis gates and the default placeholder noise model identical, but transpilation can produce different gate counts and layouts. If official processor data changes basis gates, ports, calibration, or noise, those factors can contribute and must be reported separately.

## Why both components belong in this project?
The inventory planner answers which cryptographic assets an organization should migrate first. The Grover experiment answers the separate Phase 1 architecture question: how processor topology changes execution of the same quantum solution. It is not a measurement of the cost of attacking real RSA or ECC implementations.

## What remains uncertain?
The latest organizer clarification confirms Processor A (5 qubits) and Processor B (9 qubits) for the online stage, while exact official edge lists, basis gates, ports, and noise values are not supplied. The current processor files are therefore participant-defined and provisional until any organizer-authenticated definitions or benchmark settings are supplied. Runtime is environment-dependent. The SWAP value is an estimate rather than a direct decomposition count.

## Limitations
A toy three-qubit Grover run does not estimate the cost of attacking real RSA/ECC keys. It is an educational architecture comparison, not a cryptanalytic forecast.
