"""Upload, scan, filter and export connection records."""

import hashlib
from pathlib import Path

import pandas as pd
import streamlit as st

from src.data import MODEL_FEATURES
from src.feature_info import training_statistics
from src.history import frame_records, reclassify_scan, save_scan
from src.prediction import PreprocessingError
from app.ui import page_header, select_sample
from src.scan import (
    classify, export_csv, export_html, labeled_metrics, read_upload, results_table,
    scan_batch, validate_upload,
)


def _template_csv():
    return pd.DataFrame(columns=MODEL_FEATURES).to_csv(index=False).encode("utf-8")


def render(assets):
    page_header("Batch Scan", "Upload connection records, review predictions, and export your results.")
    st.subheader("1. Choose your data")
    left, right = st.columns([1, 1])
    left.button("Try sample scan", on_click=select_sample, use_container_width=True)
    right.download_button(
        "Download template CSV", _template_csv(), file_name="sentinel_template.csv",
        mime="text/csv", use_container_width=True,
    )
    source = st.radio("Data source", ("Upload a file", "Bundled test sample"), horizontal=True, key="batch_source")
    requested_sample = st.session_state.pop("batch_sample_requested", False)
    if source == "Bundled test sample":
        try:
            content = (Path(__file__).resolve().parents[2] / "data/sample_traffic.csv").read_bytes()
        except OSError as exc:
            st.error(f"The bundled sample could not be opened: {exc}")
            return
        filename = "sample_traffic.csv"
        st.caption("Real KDDTest+ rows with recorded labels. Saved results are tagged as demo activity.")
    else:
        upload = st.file_uploader("Traffic file", type=["csv", "txt"])
        st.caption("CSV: 39 named model features. NSL-KDD TXT: 43 original fields. Limit: 100,000 rows / 30 MB.")
        if upload is None:
            st.info("Choose a file above, or try the bundled test sample to explore the full workflow.")
            return
        content = upload.getvalue()
        filename = upload.name
    digest = hashlib.sha256(content).hexdigest()
    scan_clicked = st.button("Scan connections", type="primary")
    if scan_clicked or requested_sample:
        try:
            frame = read_upload(content, filename)
            stats = training_statistics()
            ranges = {name: (item["min"], item["max"]) for name, item in stats.items()}
            checked = validate_upload(frame, assets, ranges)
        except (OSError, ValueError) as exc:
            st.error(str(exc))
            return
        if checked.errors:
            st.error("Please fix these upload issues:")
            for issue in checked.errors:
                st.write("•", issue)
            return
        progress = st.progress(0, text="Scanning rows")
        try:
            probabilities = scan_batch(
                checked.features, assets,
                progress=lambda fraction: progress.progress(fraction, text="Scanning rows"),
            )
        except (PreprocessingError, ValueError) as exc:
            progress.empty()
            st.error(f"Could not scan this upload: {exc}")
            return
        progress.empty()
        sample_file = Path(__file__).resolve().parents[2] / "data" / "sample_traffic.csv"
        is_demo = sample_file.is_file() and digest == hashlib.sha256(sample_file.read_bytes()).hexdigest()
        try:
            scan_id = save_scan(
                frame_records(checked.features, probabilities, checked.families),
                source="batch", filename=filename,
                threshold=st.session_state.get("batch_threshold", 0.5),
                medium_at=st.session_state.get("batch_medium_at", 0.5),
                high_at=st.session_state.get("batch_high_at", 0.8),
                is_demo=is_demo,
            )
        except (OSError, ValueError) as exc:
            st.error(f"Predictions succeeded, but the scan could not be saved: {exc}")
            return
        st.session_state["batch_scan"] = {
            "digest": digest, "features": checked.features, "labels": checked.labels,
            "probabilities": probabilities, "mode": checked.mode,
            "warnings": checked.warnings, "scan_id": scan_id, "is_demo": is_demo,
        }
    result = st.session_state.get("batch_scan")
    if result is None or result["digest"] != digest:
        return
    st.success(
        f"Saved scan #{result['scan_id']} with {len(result['features']):,} rows. "
        f"Category input detected: {result['mode']}."
    )
    if result["is_demo"]:
        st.caption("Demo activity: this upload matches the bundled NSL-KDD sample file.")
    if result["mode"] == "encoded integers":
        st.caption("Category integers were decoded with the v1 training encoders before prediction.")
    for warning in result["warnings"][:8]:
        st.warning(warning)
    if len(result["warnings"]) > 8:
        st.caption(f"{len(result['warnings']) - 8} more training-range warnings omitted.")

    st.divider()
    st.subheader("2. Review predictions")
    st.caption("Adjusting the threshold updates this saved scan. Lower thresholds flag more rows; severity reflects score bands, not confirmed attack impact.")
    threshold = st.slider("Anomaly threshold", 0.0, 1.0, 0.5, 0.01, key="batch_threshold")
    band_columns = st.columns(2)
    medium_at = band_columns[0].slider(
        "Medium severity from", 0.0, 1.0, 0.5, 0.01, key="batch_medium_at"
    )
    high_at = band_columns[1].slider(
        "High severity from", 0.0, 1.0, 0.8, 0.01, key="batch_high_at"
    )
    if medium_at >= high_at:
        st.error("High severity must start above Medium severity.")
        return
    reclassify_scan(result["scan_id"], threshold, medium_at, high_at)
    table = results_table(
        result["features"], result["probabilities"], threshold,
        medium_at, high_at, result["labels"],
    )
    prediction, _ = classify(result["probabilities"], threshold, medium_at, high_at)
    summary = st.columns(3)
    summary[0].metric("Rows scanned", len(table))
    summary[1].metric("Predicted anomalies", int((prediction == "Anomaly").sum()))
    summary[2].metric("Predicted normal", int((prediction == "Normal").sum()))
    metrics = None
    if result["labels"] is not None:
        metrics = labeled_metrics(prediction, result["labels"])
        st.caption("Labeled mode: the following measures use labels supplied in this upload.")
        measured = st.columns(3)
        measured[0].metric("Precision", f"{metrics['precision']:.1%}")
        measured[1].metric("Recall", f"{metrics['recall']:.1%}")
        measured[2].metric("False positives", metrics["false_positives"])
    else:
        st.caption("Unlabeled mode: outcomes cannot be scored without ground-truth labels.")

    st.subheader("Connection results")
    filter_columns = st.columns(4)
    anomaly_only = filter_columns[0].checkbox("Only anomalies")
    severity = filter_columns[1].multiselect("Severity", ["Low", "Medium", "High"])
    protocols = filter_columns[2].multiselect(
        "Protocol", sorted(table["protocol_type"].unique().tolist())
    )
    services = filter_columns[3].multiselect(
        "Service", sorted(table["service"].unique().tolist())
    )
    sort_columns = st.columns(2)
    sort_by = sort_columns[0].selectbox(
        "Sort by", ["anomaly_probability", "row", "severity", "protocol_type", "service"],
        format_func=lambda value: {"anomaly_probability": "Anomaly probability", "protocol_type": "Protocol"}.get(value, value.title()),
    )
    descending = sort_columns[1].checkbox("Descending", value=True)
    filtered = table
    if anomaly_only:
        filtered = filtered[filtered["prediction"] == "Anomaly"]
    if severity:
        filtered = filtered[filtered["severity"].isin(severity)]
    if protocols:
        filtered = filtered[filtered["protocol_type"].isin(protocols)]
    if services:
        filtered = filtered[filtered["service"].isin(services)]
    if sort_by == "severity":
        filtered = filtered.sort_values(
            sort_by, ascending=not descending,
            key=lambda values: values.map({"Low": 0, "Medium": 1, "High": 2}),
        )
    else:
        filtered = filtered.sort_values(sort_by, ascending=not descending)
    st.caption(f"Showing {len(filtered):,} of {len(table):,} results. Exports contain all scanned rows.")
    st.dataframe(
        filtered, use_container_width=True, hide_index=True,
        column_config={
            "row": "Row", "prediction": "Prediction", "severity": "Severity",
            "duration": "Duration (seconds)", "protocol_type": "Protocol", "service": "Service",
            "flag": "Connection flag", "src_bytes": "Source bytes", "dst_bytes": "Destination bytes",
            "anomaly_probability": st.column_config.ProgressColumn(
                "Anomaly probability", min_value=0, max_value=1, format="%.2f"
            )
        },
    )
    st.divider()
    st.subheader("3. Export results")
    downloads = st.columns(2)
    downloads[0].download_button(
        "Download results CSV", export_csv(table), file_name="sentinel_results.csv",
        mime="text/csv",
    )
    downloads[1].download_button(
        "Download one-page summary", export_html(
            table, threshold, medium_at, high_at, metrics=metrics
        ),
        file_name="sentinel_summary.html", mime="text/html",
    )
