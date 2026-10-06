"""Dashboard backed entirely by persisted scan history."""

import json

import pandas as pd
import streamlit as st

from src.history import dashboard_data


def _open_manual_scan():
    st.session_state["nav"] = "Manual Scan"


def render(_assets):
    st.title("🛡️ Network Security Intelligence")
    st.caption("Saved local scan history. Times are recorded in UTC.")
    data = dashboard_data()
    if not data["scans"]:
        st.info("No saved scans yet. Run a Manual Scan or upload a file in Batch Scan to start your history.")
        st.button("Open Manual Scan", on_click=_open_manual_scan)
        return

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
        st.line_chart(timeline.set_index("day")[["detections", "anomalies"]])

    services, protocols = st.columns(2)
    with services:
        st.subheader("Top services among anomalies")
        if data["top_services"]:
            st.bar_chart(pd.DataFrame(data["top_services"]).set_index("name"))
        else:
            st.caption("No predicted anomalies yet.")
    with protocols:
        st.subheader("Top protocols among anomalies")
        if data["top_protocols"]:
            st.bar_chart(pd.DataFrame(data["top_protocols"]).set_index("name"))
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
