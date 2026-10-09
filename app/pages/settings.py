"""Local scan database management."""

import sqlite3
from zipfile import BadZipFile

import pandas as pd
import streamlit as st

from src.history import (
    audit_events, database_size, dashboard_data, delete_all_data, delete_demo_data,
    export_database_csv, import_database_csv,
)
from app.ui import page_header


def render(_assets):
    page_header("Settings", "Manage local history, backups, and audit records.")
    st.caption("Scan history is stored locally in data/sentinel.db. The database is ignored by Git.")
    stats = dashboard_data()
    summary = st.columns(3)
    summary[0].metric("Saved scans", stats["scans"])
    summary[1].metric("Saved detections", stats["detections"])
    summary[2].metric("Database size", f"{database_size() / (1024 * 1024):.2f} MB")

    st.subheader("CSV backup")
    st.caption("A ZIP containing scans.csv, detections.csv, status_history.csv and audit_events.csv.")
    if st.button("Prepare database CSV bundle"):
        st.session_state["database_export"] = export_database_csv()
    if "database_export" in st.session_state:
        st.download_button(
            "Download database CSV bundle", st.session_state["database_export"],
            file_name="sentinel_database_csv.zip", mime="application/zip",
        )
    upload = st.file_uploader("Import a Sentinel CSV bundle", type=["zip"])
    replace = st.checkbox("Replace the current local database with this import")
    if st.button("Import CSV bundle", disabled=upload is None or not replace):
        try:
            imported = import_database_csv(upload.getvalue())
        except (ValueError, BadZipFile, UnicodeDecodeError, sqlite3.Error) as exc:
            st.error(f"Could not import CSV bundle: {exc}")
        else:
            st.success(f"Imported {imported} scan(s).")
            st.session_state.pop("batch_scan", None)
            st.session_state.pop("manual_result", None)
            st.session_state.pop("last_result", None)
            st.session_state.pop("database_export", None)
            st.rerun()

    st.subheader("Delete demo scans")
    st.caption("Removes scans made from the built-in NSL-KDD examples and bundled sample upload.")
    confirm_demo = st.checkbox("Confirm deletion of demo scans")
    if st.button("Delete demo scans", disabled=not confirm_demo):
        removed = delete_demo_data()
        st.success(f"Deleted {removed} demo detection(s).")
        st.session_state.pop("batch_scan", None)
        st.session_state.pop("manual_result", None)
        st.session_state.pop("last_result", None)
        st.session_state.pop("database_export", None)
        st.rerun()

    st.subheader("Delete all data")
    st.warning("This removes all scans, detections, notes and status history. A deletion receipt remains in the audit trail.")
    confirmation = st.text_input("Type DELETE to confirm", key="delete_confirmation")
    if st.button("Delete all data", disabled=confirmation != "DELETE"):
        scans, detections = delete_all_data()
        st.success(f"Deleted {scans} scan(s) and {detections} detection(s).")
        st.session_state.pop("batch_scan", None)
        st.session_state.pop("manual_result", None)
        st.session_state.pop("last_result", None)
        st.session_state.pop("database_export", None)
        st.rerun()

    st.subheader("Recent audit events")
    events = audit_events()[:20]
    if events:
        st.dataframe(pd.DataFrame(events), hide_index=True, use_container_width=True)
    else:
        st.caption("No events yet.")
