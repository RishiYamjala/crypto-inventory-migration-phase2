# ⚛️ Crypto Inventory & Migration Planner

> **Qiskit Fall Fest 2026 · Phase 1 · Problem Statement P2**
>
> Turn cryptographic inventory into a quantum-risk migration plan—and measure how the **same Grover benchmark** behaves on two processor topologies.

[![Qiskit](https://img.shields.io/badge/Qiskit-Phase%201-6929C4?logo=qiskit&logoColor=white)](https://www.ibm.com/quantum/qiskit) [![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/) [![Reproducible](https://img.shields.io/badge/experiment-reproducible-20B26B)](#reproducibility) [![AI disclosed](https://img.shields.io/badge/AI%20assistance-disclosed-555555)](#ai-assistance-disclosure)

## The thesis

**Inventory the cryptography, prioritize the migration, then measure—not guess—how processor geometry changes a quantum workload.**

```text
┌────────────────────────┐       ┌─────────────────────────────┐
│ Classical crypto       │       │ Quantum architecture study  │
│ inventory              │       │                             │
│ risk score → phase     │       │ same Grover circuit         │
│ migration plan         │       │ A → transpile → execute     │
│                        │       │ B → transpile → execute     │
└────────────┬───────────┘       └──────────────┬──────────────┘
             │                                  │
             └──────────────┬───────────────────┘
                            ▼
                 evidence-based Phase 1 report
```

## What is inside

### Part A — Crypto inventory → migration plan

- Ten-row sample inventory in `data/raw/inventory.csv`
- Auditable vulnerability, sensitivity, lifespan, and risk scoring tables
- HNDL detection for long-lived public-key assets in exposed usages
- NIST-aligned recommendations using ML-KEM, ML-DSA, SLH-DSA, AES-256, AES-256-GCM, SHA-256, and SHA-3
- Phase-based migration prioritization

### Part B — Controlled A/B benchmark

- Three-qubit Grover search for marked state `101`
- Two iterations; all qubits measured
- Identical A/B conditions: `2048` shots, optimization level `1`, seed `42`, and shared noise model
- Measured success probability, uncertainty, depth, two-qubit gates, SWAP estimate, physical qubits, total operations, runtime, and ideal reference

### Part C — Architecture evidence

- Coupling graphs
- Logical circuit drawing
- Noisy performance chart with error bars
- Depth / two-qubit-gate / SWAP trade-off chart
- Machine-readable CSV evidence

## Verified run results

These values are generated from the result CSVs—not typed in by hand.

| Metric | Processor A | Processor B | B − A |
|---|---:|---:|---:|
| Success probability for `101` | `0.583496` | `0.583496` | `0.000000` |
| Standard error | `0.010893` | `0.010893` | `0.000000` |
| Compiled depth | `175` | `175` | `0` |
| Counted two-qubit gates | `45` | `45` | `0` |
| Estimated SWAP overhead | `7.000000` | `7.000000` | `0.000000` |
| Measured SWAP instructions | `0` | `0` | `0` |
| Total compiled operations | `276` | `276` | `0` |

**Interpretation:** Processor A and Processor B produced identical measured metrics for this fixed three-qubit Grover workload; this is a workload-specific result, not evidence that their topologies are identical. This is evidence for this experiment—not a universal claim that more connectivity is always better. Gate sets, placement, routing, noise, calibration, and compiler choices can all contribute.

Full interpretation: [`report.md`](report.md) · Raw evidence: [`results/tables/`](results/tables/)

---

## Quick start

Use Python 3.11 or 3.12 in a fresh virtual environment. From Windows PowerShell:

```powershell
git clone https://github.com/RishiYamjala/crypto-inventory-migration-planner.git
cd crypto-inventory-migration-planner
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
python check_phase1_submission.py
jupyter notebook main.ipynb
```

If PowerShell cannot find `py -3.12`, install Python 3.12 first or use `python -m venv .venv` with a supported Python version. If activation is blocked by your machine's PowerShell policy, open Command Prompt and run `.venv\Scripts\activate.bat` instead.

On macOS/Linux, replace the environment creation and activation commands with:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

In Jupyter, choose **Kernel → Restart Kernel and Run All Cells**. To execute the notebook headlessly:

```bash
jupyter nbconvert --to notebook --execute main.ipynb --output executed_main.ipynb --ExecutePreprocessor.timeout=600
```

The artifact checklist checks files and basic expected fields; it does not certify scientific validity or official processor provenance. The provenance validator is a separate check and is expected to remain blocked while the organizer-authenticated manifest is pending.

## Repository map

```text
├── README.md                         ← this showcase
├── main.ipynb                        ← end-to-end experiment
├── requirements.txt                  ← environment specification
├── report.md                         ← measured analysis + limitations
├── data/raw/inventory.csv            ← sample crypto inventory
├── processors/processor_A.py         ← reproducible five-qubit model generator
├── processors/processor_B.py         ← reproducible nine-qubit model generator
├── processors/processor_A.json       ← generated five-qubit branching model
├── processors/processor_B.json       ← generated nine-qubit heavy-hex-inspired model
├── src/problem.py                    ← scoring + migration logic
├── src/processors.py                 ← JSON loading + noise model
├── src/routing.py                    ← Grover + transpilation
├── src/metrics.py                    ← A/B metrics
├── src/visualization.py              ← figures
└── results/                          ← CSV and PNG evidence
```

## Reproducibility controls

| Control | Value |
|---|---:|
| Shots | `2048` |
| Seed | `42` |
| Transpiler optimization level | `1` |
| Marked state | `101` |
| Grover iterations | `2` |
| One-qubit depolarizing error | `0.001` |
| CX depolarizing error | `0.01` |
| Readout error | `0.01` |

The SWAP value is explicitly an **estimate**: extra compiled two-qubit gates divided by three.

The image-derived coupling maps are passed to Qiskit as **directed pairs exactly as listed**; edge directionality is not verified by the supplied image and no reverse edges are fabricated. The Aer noise model is also a simplified research assumption: one-qubit depolarizing noise applies to listed non-two-qubit basis operations, CX-family depolarizing noise applies to listed two-qubit basis operations, and the readout error applies to measurements. These values are not official calibration data.

## Outputs

### Tables

- [`inventory_scored.csv`](results/tables/inventory_scored.csv)
- [`migration_plan.csv`](results/tables/migration_plan.csv)
- [`processor_A_metrics.csv`](results/tables/processor_A_metrics.csv)
- [`processor_B_metrics.csv`](results/tables/processor_B_metrics.csv)
- [`AB_comparison.csv`](results/tables/AB_comparison.csv)
- [`final_comparison.csv`](results/tables/final_comparison.csv)

### Figures

- [`processor_A_graph.png`](results/figures/processor_A_graph.png)
- [`processor_B_graph.png`](results/figures/processor_B_graph.png)
- [`logical_vs_transpiled.png`](results/figures/logical_vs_transpiled.png)
- [`AB_performance.png`](results/figures/AB_performance.png)
- [`architecture_tradeoffs.png`](results/figures/architecture_tradeoffs.png)

## Phase 1 checklist

- [x] Exactly one Problem Statement: **P2 — Crypto Inventory & Migration Planner**
- [x] Inventory scorer and migration planner
- [x] Same logical benchmark on A and B
- [x] Controlled seeds, shots, compiler settings, and noise
- [x] Transpiled circuits and measured metrics
- [x] A/B comparison, figures, and evidence-based report
- [x] Limitations and AI assistance disclosure
- [x] Processor A/B definitions are generated reproducibly from participant Python models
- [x] Online A/B architecture comparison separated from offline C/D Bell-correlation scope

## Online and offline challenge stages

The latest organizer clarification describes the online Phase 1 comparison as **Processor A: five qubits** and **Processor B: nine qubits with a heavy-hex-inspired graph**. The offline shortlisted stage introduces **Processors C and D**, a Bell-correlation study with `XX`, `YY`, and `ZZ` checks, protection strategies, and postselection yield. This repository targets the online P2 deliverable; it does not claim to implement the offline C/D package.

## Important Challenge Kit note

The supplied processor-stage image establishes reference shapes: Processor A is a five-qubit branching graph, and Processor B is a nine-qubit heavy-hex-inspired graph per the latest organizer clarification. The coupling maps in this repository are participant-defined research architectures; node labels and edge directions are explicit modeling choices, not official hidden JSON values. The **official Challenge Kit remains authoritative** for any more detailed basis gates, ports, noise assumptions, and PS-specific inputs.

Processor A and B use participant-defined coupling maps guided by the supplied reference image and the clarified 5/9-qubit counts. Their basis gates, ports, noise values, and edge directions are explicit simulator assumptions. Therefore the current benchmark is **research-defined and simulator-based**, not an official hardware result.

Run `python processors/processor_A.py` and `python processors/processor_B.py` to regenerate the JSON definitions, then rerun the notebook. Do not manually edit measured CSVs or report values. The generator scripts make the participant-defined architecture choices auditable and reproducible.

## Participant-defined processor models

Latest organizer messages clarify that Processor A has 5 qubits and Processor B has 9 qubits, and that coupling maps are participant-designed reference architectures rather than a single mandatory hidden JSON. The generators `processors/processor_A.py` and `processors/processor_B.py` write the committed JSON files used by the notebook. Processor A uses the branching-tree reference shape; Processor B uses a 9-qubit heavy-hex-inspired graph with explicit participant-selected edges. These choices are documented assumptions and remain subject to any later organizer clarification.

## Submission timing

The latest applicant announcement extends the Phase 1 deadline to **14 October 2026, 11:59 PM IST**. Submit the public GitHub repository link through the official hackathon portal.

## Limitations

A toy three-qubit Grover run **does not estimate the cost of attacking real RSA or ECC keys**. This is an educational architecture comparison, not a cryptanalytic forecast.

## AI assistance disclosure

AI assistance was used during development. The submitter should review the final code, run the tests and notebook locally, and ensure the submitted results match the generated artifacts.

## License

No license has been selected yet. Add the license required by your team or hackathon before public release.

## Authorized discovery, not unrestricted scanning

The optional `src/discovery.py` module demonstrates a safer next step beyond a static spreadsheet. It scans only a directory explicitly supplied by the user, records the matching source file and evidence excerpt, and never performs network scanning or reads outside that directory.

Run the synthetic demonstration from the notebook, or use it directly:

```python
from src.discovery import discover_directory
assets = discover_directory("data/raw/authorized_test_env")
```

Use this only against infrastructure and files for which you have explicit authorization. The generated evidence table is [`discovered_assets.csv`](results/tables/discovered_assets.csv).

## Optional dashboard

The repository also includes a local Streamlit dashboard with three views:

- **Overview** — total assets, migration-assessment count, Phase 1 count, HNDL flags
- **Inventory & roadmap** — prioritized assets, role-aware risk rationale, evidence, and next step
- **Processor A/B** — measured benchmark comparison from the CSV outputs

Launch it with:

```bash
streamlit run app.py
```

## Why the classical and quantum parts belong together

The inventory planner answers: **which cryptographic assets should an organization migrate first, and why?** The Grover experiment answers a different Phase 1 question: **how does processor architecture change execution of the same quantum solution?** The benchmark is included because the challenge requires an A/B architecture comparison; it is not a measurement of an organization's real RSA/ECC attack cost and should never be presented as one.

## Validation before submission

Run the focused migration tests:

```bash
pytest -q tests/test_problem.py
```

The tests verify that:

- key-establishment assets receive ML-KEM recommendations;
- signature/authentication assets receive ML-DSA recommendations;
- TLS certificates can require both key-exchange and certificate-signature migration;
- every scored asset receives an explainable rationale and deterministic priority rank.

The repository has not received official Challenge Kit processor definitions in the supplied materials. The A/B numbers are reproducible **simulator results from clearly labeled participant-defined 5/9-qubit research models**, not hardware measurements.

## Official-configuration gate

Public-source checking did not locate the organizer's exact Processor A/B JSON files or edge lists. The IBM Qiskit Fall Fest announcement is a general event page and does not publish these processor parameters; public GitHub searches also found no matching Challenge Kit artifact.

The supplied image is therefore recorded as a **topology reference only**. It supports the five-versus-nine-qubit distinction and the broad reference shapes, but it does not verify node labels, directed edges, basis gates, ports, compiler baseline, or noise parameters. The JSON files now include `official_challenge_kit_verified: false` and must not be presented as official configurations. The latest organizer clarification permits participant-defined coupling maps and confirms Processor B uses 9 qubits.

Run the gate with:

```bash
python validate_processors.py
```

It intentionally fails until the exact organizer-provided files are installed and both flags are changed to `true`. After that, rerun `main.ipynb`, regenerate all result tables/figures/report text, run `pytest -q`, and only then mark the Phase 1 submission ready.

## Authenticity validation

`official_challenge_kit_verified: true` is **not sufficient** for acceptance. The repository now requires an organizer-supplied `processors/challenge_kit_manifest.json` with:

- an authoritative source reference;
- a configuration version;
- expected qubit counts;
- exact coupling maps;
- exact basis gates;
- exact ports;
- exact noise parameters; and
- a SHA-256 hash for each processor JSON file.

Run:

```bash
python validate_processors.py
```

The committed manifest is intentionally `pending`, so the validator fails until the real Challenge Kit manifest is installed. It then compares every required value and the complete file hash before accepting the configuration. This prevents a user from merely changing a Boolean flag to claim official status.

## Current submission status

| Requirement | Status |
|---|---|
| Crypto migration functionality | Implemented; regression tests are included |
| Notebook execution | Must be rerun in the submitter's current environment before submission |
| Processor provenance safeguards | Implemented |
| Official Processor A/B authenticity | **Pending organizer-supplied manifest** |
| Benchmark using official configurations | **Not established yet** |

The validator separates two claims:

- **Authenticity:** the manifest must come from an authoritative organizer source and identify a version.
- **Integrity and consistency:** processor files must match the manifest's exact fields and SHA-256 hashes.

A hash created from this repository's own placeholders would prove only self-consistency, not official origin. For that reason, the pending manifest remains blocked until the organizer supplies the source artifact or exact signed/referenceable specification.

## Official guideline alignment

The supplied [`QFF_IBM_Hackathon_Guideline.pdf`](docs/QFF_IBM_Hackathon_Guideline.pdf) confirms that Phase 1 is an online A/B comparison. The latest organizer clarification specifies Processor A with 5 qubits and Processor B with 9 qubits; teams must report solution quality, circuit cost, routing/SWAP overhead, physical qubits, noise assumptions, reproducibility, graphs, circuits, and scientific interpretation. The repository includes those artifacts.

The PDF does **not** include the exact Processor A/B JSON definitions or complete edge lists. It therefore confirms the benchmark *requirements*, not the authenticity of the current processor parameters. See [`docs/PHASE1_COMPLIANCE.md`](docs/PHASE1_COMPLIANCE.md) for the evidence map and the pending official-configuration gate.


Run the online artifact checklist with:

```bash
python check_phase1_submission.py
```

The official Drive folder also contains the participant instructions and starter guide, preserved here as [`QFF_2026_Hackathon_Phase1_Participant_Instructions.pdf`](docs/QFF_2026_Hackathon_Phase1_Participant_Instructions.pdf) and [`Challenge_Guide_Phase_1.pdf`](docs/Challenge_Guide_Phase_1.pdf). The starter guide's processor JSON on page 15 is explicitly illustrative and says to replace every value with the exact organizer-supplied definition. See [`docs/PROCESSOR_CONFIG_STATUS.md`](docs/PROCESSOR_CONFIG_STATUS.md) for the source-by-source finding.

The uploaded applicant communications clarify the intended scope: there is no downloadable dataset, Challenge Kit, or Processor A/B/C JSON; participants are expected to research and simulate the published processor topologies. Accordingly, this repository presents its A/B models as **research simulations**, not hidden official configurations. The exact topology assumptions and limitations remain documented rather than silently asserted as fact.

## Automated validation and limitations

The repository includes regression tests for migration recommendations, processor-driven noise, and topology-sensitive transpilation, plus a CI workflow for Python 3.11 and 3.12. CI runs the tests and the online artifact checklist. These automated checks do not replace a fresh end-to-end notebook run or organizer review.

Before submitting, run `python -m pytest -q`, `python check_phase1_submission.py`, and execute every cell in `main.ipynb` in a clean environment. Confirm that regenerated tables, figures, and report agree. The official processor authenticity validator is expected to fail while the organizer-authenticated manifest is pending; do not represent participant-defined models as official configurations.

The benchmark remains a simulator experiment using participant-defined 5/9-qubit research models. Its three-qubit Grover results do not estimate the cost of attacking real RSA/ECC keys.
