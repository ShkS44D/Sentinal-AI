"""Shared blue-and-white interface components and navigation callbacks."""
from pathlib import Path

import streamlit as st

SHIELD = '<svg width="36" height="40" viewBox="0 0 32 36" fill="none" aria-hidden="true"><path d="M16 3L29 9v10c0 8-8 13-13 15C11 32 3 27 3 19V9L16 3Z" stroke="currentColor" stroke-width="2"/><path d="m10 18 4 4 8-9" stroke="currentColor" stroke-width="2"/></svg>'


def apply_style():
    st.markdown(f"<style>{Path(__file__).with_name('style.css').read_text()}</style>", unsafe_allow_html=True)


def brand():
    st.markdown(f'<div class="sentinel-brand">{SHIELD}<div><strong>Sentinel IDS</strong><span>Intrusion detection prototype</span></div></div>', unsafe_allow_html=True)


def page_header(title, description):
    st.title(title)
    st.caption(description)
    st.divider()


def navigate(page, *, sample=False):
    st.session_state["nav"] = page
    if sample:
        select_sample()


def select_sample():
    st.session_state["batch_source"] = "Bundled test sample"
    st.session_state["batch_sample_requested"] = True


def workflow():
    st.markdown('<div class="workflow"><span><b>01</b> Prepare data</span><span class="flow-arrow">→</span><span><b>02</b> Scan connections</span><span class="flow-arrow">→</span><span><b>03</b> Investigate alerts</span></div>', unsafe_allow_html=True)


def chart_style(figure):
    figure.update_layout(template="plotly_white", paper_bgcolor="white", plot_bgcolor="white",
                         font_color="#172b4d", colorway=["#2563eb", "#89aef8"],
                         margin=dict(l=16, r=16, t=24, b=32), height=300,
                         legend_title_text="")
    return figure
