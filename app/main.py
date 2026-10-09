"""Sentinel IDS Streamlit entry point."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st
from app.access import require_login
from src.auth import permitted
from src.model import ModelLoadError, load_assets
from app.ui import apply_style, brand

def main():
    st.set_page_config(page_title="Sentinel IDS | Network Intrusion Detection", layout="wide")
    apply_style()
    with st.sidebar:
        brand()
    role = require_login()
    try:
        assets = load_assets()
    except ModelLoadError as exc:
        st.error(str(exc))
        st.stop()
    with st.sidebar:
        pages = ["Dashboard", "Manual Scan", "Batch Scan", "Alerts",
                 "Sample Detection", "Flow Import", "AI Analytics", "Settings"]
        pages = [name for name in pages if permitted(role, name)]
        if st.session_state.get("nav") not in pages:
            st.session_state["nav"] = "Dashboard"
        page = st.radio(
            "WORKSPACE",
            pages,
            key="nav",
            format_func=lambda name: {"Dashboard": "Overview", "AI Analytics": "Model Insights"}.get(name, name),
        )
        st.divider()
        st.caption("Model v1 · NSL-KDD benchmark")
        st.caption("Binary Normal / Anomaly. No live packet capture.")
        if st.session_state.get("local_demo_mode"):
            st.caption("Local demo mode · accounts not configured")
    if page == "Dashboard":
        from app.pages.dashboard import render
    elif page == "Manual Scan":
        from app.pages.manual import render
    elif page == "Batch Scan":
        from app.pages.batch import render
    elif page == "Alerts":
        from app.pages.alerts import render
    elif page == "Settings":
        from app.pages.settings import render
    elif page == "Sample Detection":
        from app.pages.detection import render
    elif page == "Flow Import":
        from app.pages.flows import render
    else:
        from app.pages.analytics import render
    render(assets)

if __name__ == "__main__":
    main()
