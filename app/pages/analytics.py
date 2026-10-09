"""Global model feature importance."""
import pandas as pd
import plotly.express as px
import streamlit as st
import json
import hashlib
from pathlib import Path
from app.ui import chart_style, page_header

def render(assets):
    page_header("Model Insights", "Understand measured performance, prediction limits, and feature importance.")
    root = Path(__file__).resolve().parents[2]
    try:
        metrics = json.loads((root / "reports/metrics.json").read_text())
        reliability = json.loads((root / "reports/reliability.json").read_text())
        if reliability["model_sha256"] != hashlib.sha256((root / "models/v1/model.joblib").read_bytes()).hexdigest():
            raise ValueError("Reliability report belongs to a different model.")
    except (OSError, ValueError):
        st.info("Reliability report is unavailable. Run python -m src.reliability after downloading the official test set.")
    else:
        st.subheader("Reliability on the official test set")
        st.caption(f"{reliability['dataset']} · {reliability['split']} · {reliability['rows']:,} rows · threshold 0.5")
        st.caption("This view uses probability ≥ threshold, matching Manual and Batch Scan. The original evaluation report uses the forest's predict method, which treats exact 0.5 ties as Normal; counts can differ.")
        baseline = next(row for row in reliability["thresholds"] if row["threshold"] == 0.5)
        columns = st.columns(3)
        columns[0].metric("Anomalies missed", baseline["fn"])
        columns[1].metric("Anomaly recall", f"{baseline['recall']:.1%}")
        columns[2].metric("False alarms", baseline["fp"])
        st.warning("Many test anomalies are missed. Results on this old benchmark do not establish performance on your network. Probability scores are not calibrated guarantees.")
        st.write("Errors by recorded attack family")
        st.caption("The model predicts Normal/Anomaly only. Families below are dataset labels, not model predictions. For Normal, the rate measures correctly accepted normal rows.")
        st.dataframe(pd.DataFrame(reliability["families"]), hide_index=True)
        st.write("Threshold trade-offs on KDDTest+")
        st.caption("These are test-set observations, not promised outcomes for new uploads. Choosing a threshold based on these results makes the test set part of tuning.")
        st.dataframe(pd.DataFrame(reliability["thresholds"]), hide_index=True)
        st.write("Probability versus observed anomaly rate")
        calibration = pd.DataFrame(reliability["calibration"])
        comparison = px.bar(calibration, x="band", y=["mean_probability", "observed_anomaly_rate"], barmode="group",
                            labels={"band": "Probability band", "value": "Rate", "variable": "Measure"})
        st.plotly_chart(chart_style(comparison), use_container_width=True)
        st.caption(f"Brier score: {reliability['brier_score']:.4f} (lower is better). Raw forest probabilities; no calibration fitted on the test set.")
        st.download_button("Download reliability report", json.dumps({"evaluation": metrics, "reliability": reliability}, indent=2), "sentinel_reliability.json")
    st.write("Global feature importance for the saved binary normal versus anomaly classifier.")
    st.caption("These scores describe the model overall; they do not explain an individual prediction or identify an attack type.")
    frame = pd.DataFrame(
        {"Feature": assets.feature_names, "Importance": assets.model.feature_importances_}
    ).nlargest(10, "Importance").sort_values("Importance")
    figure = px.bar(
        frame, x="Importance", y="Feature", orientation="h", template="plotly_white",
        color="Importance", color_continuous_scale="Blues",
    )
    figure.update_layout(showlegend=False, paper_bgcolor="white", plot_bgcolor="white", font_color="#172b4d")
    st.plotly_chart(figure, use_container_width=True)
    st.caption("Measured test performance and evaluation plots are in reports/metrics.md and reports/figures/.")
