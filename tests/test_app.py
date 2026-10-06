"""Smoke checks for all Streamlit pages and the sample scan flow."""
from pathlib import Path

from streamlit.testing.v1 import AppTest
from src.history import get_detection


APP = Path(__file__).resolve().parents[1] / "app" / "main.py"


def test_pages_and_scan_flow(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "sentinel.db"))
    app = AppTest.from_file(str(APP)).run(timeout=30)
    assert not app.exception
    assert any("No saved scans yet" in item.value for item in app.info)
    app.button[0].click().run(timeout=30)
    assert not app.exception
    assert app.sidebar.radio[0].value == "Manual Scan"
    app.sidebar.radio[0].set_value("Dashboard").run(timeout=30)
    assert not app.exception

    app.sidebar.radio[0].set_value("Sample Detection").run(timeout=30)
    assert not app.exception
    app.button[0].click().run(timeout=30)
    assert not app.exception
    assert "Reveal ground truth" in [toggle.label for toggle in app.toggle]
    assert not any("Recorded label:" in item.value for item in app.markdown)
    app.button[1].click().run(timeout=30)
    assert not app.exception

    app.sidebar.radio[0].set_value("Dashboard").run(timeout=30)
    assert app.metric[0].label == "Total scans"
    assert app.metric[0].value == "1"
    restarted = AppTest.from_file(str(APP)).run(timeout=30)
    assert restarted.metric[0].value == "1"

    app.sidebar.radio[0].set_value("AI Analytics").run(timeout=30)
    assert not app.exception


def test_new_scan_pages_render(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "sentinel.db"))
    app = AppTest.from_file(str(APP)).run(timeout=30)
    app.sidebar.radio[0].set_value("Manual Scan").run(timeout=30)
    assert not app.exception
    assert len(app.number_input) + len(app.selectbox) == 39
    app.button[1].click().run(timeout=30)
    assert not app.exception
    app.button[2].click().run(timeout=30)
    assert not app.exception
    assert any(metric.label == "Anomaly probability" for metric in app.metric)
    saved = get_detection(1, tmp_path / "sentinel.db")
    assert saved["is_demo"] == 1
    assert saved["family"] in {"DoS", "Probe", "R2L", "U2R"}
    app.sidebar.radio[0].set_value("Batch Scan").run(timeout=30)
    assert not app.exception
    assert any(title.value == "📂 Batch Scan" for title in app.title)
    app.sidebar.radio[0].set_value("Alerts").run(timeout=30)
    assert not app.exception
    app.sidebar.radio[0].set_value("Settings").run(timeout=30)
    assert not app.exception
