"""Persistent anomaly alert queue and investigation view."""

from math import ceil

import pandas as pd
import streamlit as st

from src.history import (
    SORTS, STATUSES, alert_filter_options, export_alerts_csv, get_detection,
    query_alerts, status_timeline, update_alerts,
)
from src.investigation import explain_alert


def render(_assets):
    st.title("🚨 Alerts")
    st.caption("Predicted anomalies from saved scans. Status and notes stay available after restart.")
    options = alert_filter_options()
    controls = st.columns(3)
    search = controls[0].text_input("Search ID, features or notes")
    statuses = controls[1].multiselect("Status", STATUSES)
    severities = controls[2].multiselect("Severity", ("High", "Medium", "Low"))
    more = st.columns(4)
    protocols = more[0].multiselect("Protocol", options["protocol_type"])
    services = more[1].multiselect("Service", options["service"])
    start_date = more[2].date_input("From date", value=None)
    end_date = more[3].date_input("To date", value=None)
    if start_date and end_date and start_date > end_date:
        st.error("From date must be on or before To date.")
        return
    controls = st.columns(2)
    sort = controls[0].selectbox("Sort alerts", list(SORTS))
    page_size = controls[1].selectbox("Rows per page", (25, 50, 100))
    filters = {
        "search": search, "statuses": statuses, "severities": severities,
        "protocols": protocols, "services": services, "start_date": start_date,
        "end_date": end_date, "sort": sort,
    }
    fingerprint = repr(filters) + str(page_size)
    if st.session_state.get("alert_filter_fingerprint") != fingerprint:
        st.session_state["alert_page"] = 1
        st.session_state["alert_filter_fingerprint"] = fingerprint
    page = st.session_state.get("alert_page", 1)
    rows, total = query_alerts(**filters, page=page, page_size=page_size)
    max_page = max(1, ceil(total / page_size))
    if page > max_page:
        page = max_page
        st.session_state["alert_page"] = page
        rows, total = query_alerts(**filters, page=page, page_size=page_size)

    st.metric("Matching alerts", total)
    if not total:
        st.info("No anomalies match these filters. Run a scan or adjust the filters.")
        return
    columns = ("id", "timestamp", "severity", "status", "probability",
               "protocol_type", "service", "source", "is_demo")
    table = pd.DataFrame(rows)[list(columns)].rename(columns={"is_demo": "demo"})
    st.dataframe(
        table, hide_index=True, use_container_width=True,
        column_config={"probability": st.column_config.ProgressColumn(
            "Anomaly probability", min_value=0, max_value=1, format="%.2f"
        )},
    )
    paging = st.columns([1, 2, 1])
    if paging[0].button("← Previous", disabled=page <= 1):
        st.session_state["alert_page"] = page - 1
        st.rerun()
    paging[1].caption(f"Page {page} of {max_page}")
    if paging[2].button("Next →", disabled=page >= max_page):
        st.session_state["alert_page"] = page + 1
        st.rerun()

    if st.button("Prepare filtered alerts CSV"):
        st.session_state["alerts_export"] = (fingerprint, export_alerts_csv(**filters))
    prepared = st.session_state.get("alerts_export")
    if prepared and prepared[0] == fingerprint:
        st.download_button(
            "Download filtered alerts CSV", prepared[1],
            file_name="sentinel_alerts.csv", mime="text/csv",
        )

    st.subheader("Bulk actions")
    current_ids = [row["id"] for row in rows]
    selected = st.multiselect("Select alert IDs on this page", current_ids)
    action = st.selectbox("Set status", ("No status change", *STATUSES))
    bulk_note = st.text_area("Add note to selected alerts", key="bulk_alert_note")
    if st.button("Apply to selected"):
        try:
            changed = update_alerts(
                selected, status=None if action == "No status change" else action,
                note=bulk_note,
            )
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.success(f"Updated {changed} alert(s).")
            st.rerun()

    st.subheader("Alert Detail")
    alert_id = st.selectbox("Open alert ID", current_ids)
    detail = get_detection(alert_id)
    if detail is None:
        st.warning("This alert is no longer available.")
        return
    st.caption(
        f"Scan #{detail['scan_id']} · {detail['timestamp']} UTC · "
        f"Model {detail['model_version']} · Source {detail['source']}"
        + (" · DEMO SAMPLE" if detail["is_demo"] else "")
    )
    headline = st.columns(3)
    headline[0].metric("Anomaly probability", f"{detail['probability']:.1%}")
    headline[1].metric("Severity", detail["severity"])
    headline[2].metric("Status", detail["status"])
    st.info("Feature observations (descriptive heuristics; not a model explanation): "
            + explain_alert(detail["features"]))
    if detail["family"]:
        st.caption(f"Dataset family label: {detail['family']} (provided with the scanned row)")
    st.write("Full connection features")
    st.dataframe(
        pd.DataFrame([{"Feature": key, "Value": value} for key, value in detail["features"].items()]),
        hide_index=True, use_container_width=True,
    )
    with st.form(f"investigate_{alert_id}"):
        new_status = st.selectbox(
            "Status", STATUSES, index=STATUSES.index(detail["status"]),
        )
        note = st.text_area("Add analyst note")
        save = st.form_submit_button("Save investigation")
    if save:
        try:
            update_alerts([alert_id], status=new_status, note=note)
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.rerun()
    if detail["analyst_note"]:
        st.write("Analyst notes")
        st.text(detail["analyst_note"])
    st.write("Status timeline")
    st.dataframe(pd.DataFrame(status_timeline(alert_id)), hide_index=True, use_container_width=True)
