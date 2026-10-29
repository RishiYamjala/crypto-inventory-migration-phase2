"""Optional local dashboard: streamlit run app.py"""
from pathlib import Path
import csv
import pandas as pd
import streamlit as st

from src.dashboard_inventory import predict_inventory_csv_bytes, serialize_predictions_csv

ROOT = Path(__file__).parent
TABLES = ROOT / "results" / "tables"

st.set_page_config(page_title="Quantum Readiness Overview", page_icon="⚛️", layout="wide")
st.title("⚛️ Quantum Readiness Overview")
st.caption("P2 prototype: authorized evidence → explainable inventory risk → migration roadmap → architecture benchmark")

scored = pd.read_csv(TABLES / "inventory_scored.csv")
comparison = pd.read_csv(TABLES / "final_comparison.csv")

page = st.sidebar.radio("Explore", ["Overview", "Phase 2 CSV planner", "Phase 1 Inventory & roadmap", "Processor A/B"])

if page == "Overview":
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Cryptographic assets", len(scored))
    c2.metric("Assets requiring assessment", int((scored["risk_level"] != "Safe").sum()))
    c3.metric("Phase 1 assets", int(scored["phase"].str.startswith("Phase 1").sum()))
    c4.metric("HNDL flagged", int(scored["HNDL"].sum()))
    st.subheader("What this prototype proves")
    st.markdown("""
    - The inventory scorer explains *why* an asset is risky instead of treating every non-PQC algorithm identically.
    - The migration roadmap prioritizes by phase, risk score, and sensitivity.
    - The Qiskit benchmark is a separate architecture study: it does **not** estimate the cost of attacking real RSA/ECC keys.
    - Processor definitions are placeholders until the official Challenge Kit values are supplied.
    """)
    st.bar_chart(scored.groupby("phase").size().rename("assets"))
elif page == "Phase 2 CSV planner":
    st.subheader("Phase 2 — inventory to migration plan")
    st.markdown(
        "Upload an inventory CSV to run the **same classifier and scoring rules as "
        "`run_inventory.py`**. The generated file keeps the required eight-column output "
        "schema and can be downloaded for submission or review."
    )
    st.caption(
        "This is a transparent heuristic, not the organizer's official evaluator. "
        "Unknown or ambiguous records are sent to manual review; no Macro-F1, precision, "
        "or recall is claimed without reviewed ground truth."
    )
    sample_path = ROOT / "examples" / "phase2_inventory_demo.csv"
    if sample_path.is_file():
        st.download_button(
            "Download sample inventory CSV",
            data=sample_path.read_bytes(),
            file_name="inventory_sample.csv",
            mime="text/csv",
        )

    uploaded = st.file_uploader("Upload inventory CSV", type=["csv"], key="phase2_inventory_upload")
    if uploaded is not None:
        try:
            predictions = predict_inventory_csv_bytes(uploaded.getvalue())
            prediction_frame = pd.DataFrame(predictions)
            csv_output = serialize_predictions_csv(predictions)
        except (OSError, csv.Error, UnicodeError, ValueError, TypeError) as exc:
            st.error(f"Could not process this inventory: {exc}")
        else:
            count = len(prediction_frame)
            review_count = int((prediction_frame["predicted_label"] == "UNKNOWN").sum())
            wave1_count = int((prediction_frame["migration_wave"] == "Wave 1").sum())
            urgent_count = int(
                prediction_frame["predicted_label"].isin(["QUANTUM_VULNERABLE", "LEGACY_BROKEN"]).sum()
            )
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Assets planned", count)
            c2.metric("Wave 1", wave1_count)
            c3.metric("Quantum-vulnerable / legacy", urgent_count)
            c4.metric("Manual review", review_count)

            st.subheader("Generated migration plan")
            st.dataframe(prediction_frame, use_container_width=True, hide_index=True)
            st.download_button(
                "Download eight-column migration plan",
                data=csv_output,
                file_name="inventory_migration_plan.csv",
                mime="text/csv",
            )
            st.bar_chart(prediction_frame["predicted_label"].value_counts().rename("Assets"))
            with st.expander("How to interpret this output"):
                st.markdown(
                    "- **Wave 1:** highest-priority migration under the repository's documented heuristic.\n"
                    "- **Wave 2:** remaining known quantum-vulnerable or legacy-broken assets.\n"
                    "- **Wave 3:** other recognized algorithms retained subject to policy review.\n"
                    "- **review / UNKNOWN:** metadata is missing, unrecognized, or contradictory; "
                    "do not assume the asset is safe.\n\n"
                    "Scores use the fixed base + exposure + retention + criticality formula and are "
                    "capped at 100. Confirm algorithm role, exact parameters, interoperability, and "
                    "organizational policy before making production changes."
                )

elif page == "Phase 1 Inventory & roadmap":
    st.subheader("Prioritized migration roadmap")
    st.dataframe(scored[["priority_rank", "asset_name", "algorithm", "cryptographic_role", "risk_level", "risk_score", "HNDL", "migration", "phase"]], use_container_width=True, hide_index=True)
    selected = st.selectbox("Inspect evidence", scored["asset_name"].tolist())
    row = scored.loc[scored["asset_name"] == selected].iloc[0]
    st.info(f"**Risk rationale:** {row['risk_rationale']}\n\n**Next step:** {row['migration']} ({row['migration_effort']} effort).")
else:
    st.subheader("Measured Processor A/B comparison")
    metric = st.selectbox("Metric", ["success_probability", "depth", "two_qubit_gates", "swap_estimate", "total_ops"])
    chart = comparison[comparison["Metric"] == metric].set_index("Metric")[["Processor A", "Processor B"]]
    st.bar_chart(chart)
    st.dataframe(comparison, use_container_width=True, hide_index=True)
    st.caption("All values come from the generated CSVs. Runtime and topology figures are simulator/environment evidence, not hardware claims.")
