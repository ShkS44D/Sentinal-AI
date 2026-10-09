"""Real network connection log review."""
import streamlit as st

from src.flows import flow_csv, read_flows
from app.ui import page_header


def render(_assets):
    page_header("Flow Import", "Inspect real network connection logs and export the reviewed records.")
    st.write("Review an existing Zeek conn.log exported as JSON, one connection per line.")
    st.info("Review only: these logs do not provide the 39 NSL-KDD features required by the current model. No anomaly scores, missing-feature defaults or detection history are created.")
    st.caption("Fields follow the Zeek connection log schema: https://docs.zeek.org/en/current/reference/logs/conn.html")
    upload = st.file_uploader("Zeek connection log", type=["log", "jsonl", "ndjson"])
    if upload is None:
        return
    try:
        frame = read_flows(upload.getvalue())
    except ValueError as exc:
        st.error(str(exc))
        return
    columns = st.columns(3)
    columns[0].metric("Imported connections", len(frame))
    columns[1].metric("Source addresses", frame["id.orig_h"].nunique())
    columns[2].metric("Destination addresses", frame["id.resp_h"].nunique())
    protocols = st.multiselect("Filter protocol", sorted(frame["proto"].astype(str).unique()))
    if protocols:
        frame = frame[frame["proto"].isin(protocols)]
    st.caption(f"Showing {len(frame):,} connections; missing optional fields remain blank.")
    st.dataframe(frame, hide_index=True, use_container_width=True)
    st.download_button("Export reviewed connections", flow_csv(frame), "sentinel_connections.csv", "text/csv")
