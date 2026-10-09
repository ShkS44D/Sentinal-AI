"""Dashboard backed entirely by persisted scan history."""

import json

import pandas as pd
import streamlit as st
import plotly.express as px

from src.history import dashboard_data
from app.ui import SHIELD, chart_style, navigate, page_header, workflow


def _open_manual_scan():
    st.session_state["nav"] = "Manual Scan"


def render(_assets):
    page_header("Overview", "Review saved scans and investigate predicted anomalies.")
    workflow()
    data = dashboard_data()
    if not data["scans"]:
        with st.container(border=True, key="start_panel"):
            st.markdown(f'<div class="empty-intro">{SHIELD}<h2>Your investigation starts here</h2><p>No saved scans yet. Choose a real test sample or upload connection records.</p></div>', unsafe_allow_html=True)
            actions = st.columns([1, 2, 2, 1])
            actions[1].button("Try sample scan", type="primary", on_click=navigate,
                              args=("Batch Scan",), kwargs={"sample": True}, use_container_width=True)
            actions[2].button("Open Manual Scan", on_click=_open_manual_scan, use_container_width=True)
        st.divider()
        left, right = st.columns(2, gap="large")
        with left:
            st.subheader("Scan your records")
            st.caption("Upload the 39 model features in CSV or original NSL-KDD format.")
            st.button("Open Batch Scan", on_click=navigate, args=("Batch Scan",))
        with right:
            st.subheader("Understand the model")
            st.caption("Review measured test results and the limitations behind every prediction.")
            st.button("View model insights", on_click=navigate, args=("AI Analytics",))
        st.divider()
        st.caption("NSL-KDD benchmark · Binary Normal / Anomaly · No live packet capture")
        return

    actions = st.columns([1, 1, 1, 3])
    actions[0].button("New batch scan", type="primary", on_click=navigate, args=("Batch Scan",), use_container_width=True)
    actions[1].button("Manual scan", on_click=navigate, args=("Manual Scan",), use_container_width=True)
    actions[2].button("Review alerts", on_click=navigate, args=("Alerts",), use_container_width=True)
    st.caption("Saved local scan history · all times in UTC")

    totals = st.columns(4)
    totals[0].metric("Total scans", data["scans"])
    totals[1].metric("Total detections", data["detections"])
    totals[2].metric("Predicted anomalies", data["anomalies"])
    totals[3].metric("Anomaly rate", f"{data['anomaly_rate']:.1%}")
    if data["demo_scans"]:
        st.caption(
            f"Includes {data['demo_scans']} clearly tagged demo scan(s) "
            f"and {data['demo_detections']} demo detection(s) from NSL-KDD examples. "
            "Delete them in Settings."
        )

    st.subheader("Open alerts")
    st.caption("Open means New, Investigating, or Confirmed. Resolved and False Positive are closed.")
    left, right = st.columns(2)
    with left:
        st.write("By status")
        statuses = pd.DataFrame(
            [{"Status": name, "Alerts": data["open_by_status"].get(name, 0)}
             for name in ("New", "Investigating", "Confirmed")]
        )
        st.dataframe(statuses, hide_index=True, use_container_width=True)
    with right:
        st.write("By severity")
        severities = pd.DataFrame(
            [{"Severity": name, "Alerts": data["open_by_severity"].get(name, 0)}
             for name in ("High", "Medium", "Low")]
        )
        st.dataframe(severities, hide_index=True, use_container_width=True)

    st.subheader("Detections over time")
    timeline = pd.DataFrame(data["over_time"])
    if timeline.empty:
        st.info("No detections have been saved.")
    else:
        chart = px.line(timeline, x="day", y=["detections", "anomalies"], markers=True,
                        labels={"day": "Date (UTC)", "value": "Connections", "variable": "Series"})
        st.plotly_chart(chart_style(chart), use_container_width=True)

    services, protocols = st.columns(2)
    with services:
        st.subheader("Top services among anomalies")
        if data["top_services"]:
            chart = px.bar(pd.DataFrame(data["top_services"]), x="name", y="count",
                           labels={"name": "Service", "count": "Anomalies"})
            st.plotly_chart(chart_style(chart), use_container_width=True)
        else:
            st.caption("No predicted anomalies yet.")
    with protocols:
        st.subheader("Top protocols among anomalies")
        if data["top_protocols"]:
            chart = px.bar(pd.DataFrame(data["top_protocols"]), x="name", y="count",
                           labels={"name": "Protocol", "count": "Anomalies"})
            st.plotly_chart(chart_style(chart), use_container_width=True)
        else:
            st.caption("No predicted anomalies yet.")

    st.subheader("Recent activity")
    activity = []
    for event in data["recent"]:
        details = json.loads(event["details"])
        description = {
            "scan_created": f"Scan #{details.get('scan_id')} saved · {details.get('rows')} rows",
            "status_changed": f"Alert #{details.get('detection_id')}: "
                              f"{details.get('old_status')} → {details.get('new_status')}",
            "note_added": f"Note added to alert #{details.get('detection_id')}",
            "threshold_changed": f"Threshold changed for scan #{details.get('scan_id')}",
            "demo_data_deleted": "Demo scan data deleted",
            "all_data_deleted": "All scan data deleted",
            "database_imported": "CSV database bundle imported",
        }.get(event["event_type"], event["event_type"])
        activity.append({"Time (UTC)": event["timestamp"], "Activity": description})
    st.dataframe(pd.DataFrame(activity), hide_index=True, use_container_width=True)
