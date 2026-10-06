"""Sentinel IDS Streamlit entry point."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st
from src.model import ModelLoadError, load_assets

def main():
    st.set_page_config(page_title="Sentinel IDS | Network Intrusion Detection", page_icon="🛡️", layout="wide")
    st.markdown(
        """<style>
        .stApp {background-color:#0e1117;color:#fff}
        [data-testid="stMetricValue"] {color:#00d4ff;font-weight:700}
        section[data-testid="stSidebar"] {background-color:#161b22}
        .stButton>button {border-radius:8px}
        </style>""",
        unsafe_allow_html=True,
    )
    try:
        assets = load_assets()
    except ModelLoadError as exc:
        st.error(str(exc))
        st.stop()
    with st.sidebar:
        st.title("🛡️ Sentinel IDS")
        st.caption("NSL-KDD demonstration")
        page = st.radio(
            "COMMAND CENTER",
            ("Dashboard", "Manual Scan", "Batch Scan", "Alerts", "Settings",
             "Sample Detection", "AI Analytics"),
            key="nav",
        )
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
    else:
        from app.pages.analytics import render
    render(assets)

if __name__ == "__main__":
    main()
