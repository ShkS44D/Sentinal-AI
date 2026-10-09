"""Reliability arithmetic, flow rejection, sensitivity and account boundaries."""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from src.auth import hash_password, load_users, permitted, verify_password
from src.flows import flow_csv, read_flows
from src.investigation import sensitivity_evidence
from src.model import load_assets
from src.reliability import error_analysis, threshold_metrics


def test_passwords_and_roles(monkeypatch, tmp_path):
    stored = hash_password("a-long-test-password")
    assert verify_password("a-long-test-password", stored)
    assert not verify_password("wrong-password", stored)
    assert not verify_password("password", "broken")
    with pytest.raises(ValueError):
        hash_password("short")
    assert permitted("admin", "Settings")
    assert not permitted("analyst", "Settings")
    assert permitted("analyst", "Alerts")
    assert not permitted("unknown", "Dashboard")
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"analyst": {"role": "analyst", "password_hash": stored}}))
    monkeypatch.setenv("SENTINEL_USERS_FILE", str(path))
    assert load_users()["analyst"]["role"] == "analyst"
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "history.db"))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app/main.py")).run(timeout=30)
    assert not app.exception
    assert not app.sidebar.radio
    app.text_input[0].set_value("analyst")
    app.text_input[1].set_value("a-long-test-password")
    app.button[0].click().run(timeout=30)
    assert not app.exception
    assert "Settings" not in app.sidebar.radio[0].options
    app.sidebar.button[0].click().run(timeout=30)
    assert not app.sidebar.radio


def test_account_configuration_fails_closed(monkeypatch, tmp_path):
    path = tmp_path / "users.json"
    path.write_text('{"bad": {"role": "owner"}}')
    monkeypatch.setenv("SENTINEL_USERS_FILE", str(path))
    with pytest.raises(ValueError):
        load_users()


def test_reliability_counts():
    metrics = threshold_metrics([0, 0, 1, 1], [0.1, 0.8, 0.2, 0.9], 0.5)
    assert (metrics["tn"], metrics["fp"], metrics["fn"], metrics["tp"]) == (1, 1, 1, 1)
    assert metrics["recall"] == metrics["precision"] == 0.5
    frame = pd.DataFrame({"label_binary": [0, 0, 1, 1], "attack_family": ["Normal", "Normal", "DoS", "DoS"]})
    report = error_analysis(frame, [0, 0.8, 0.2, 1])
    assert sum(row["rows"] for row in report["calibration"]) == 4
    assert all(row["binary_detection_rate"] == 0.5 for row in report["families"])
    assert threshold_metrics([0], [0], 0.5)["precision"] == 0
    assert threshold_metrics([1], [0.5], 0.5)["tp"] == 1


def test_flow_import_and_export():
    record = {"ts": 1700000000, "proto": "tcp", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "orig_bytes": 123}
    frame = read_flows(json.dumps(record).encode())
    assert frame["orig_bytes"].iloc[0] == 123
    assert pd.isna(frame["resp_bytes"].iloc[0])
    assert "probability" not in frame
    assert b"timestamp_utc" in flow_csv(frame)
    for content in (b"", b"not json", b"[]", b"{}", json.dumps({**record, "orig_bytes": -1}).encode(), json.dumps({**record, "ts": None}).encode(), json.dumps({**record, "id.orig_h": "bad"}).encode(), json.dumps({**record, "id.orig_p": 65536}).encode()):
        with pytest.raises(ValueError):
            read_flows(content)


def test_generated_reliability_report():
    report = json.loads((Path(__file__).resolve().parents[1] / "reports/reliability.json").read_text())
    assert report["rows"] == sum(row["rows"] for row in report["families"])
    assert report["rows"] == sum(row["rows"] for row in report["calibration"])
    assert len(report["model_sha256"]) == len(report["test_sha256"]) == 64
    for row in report["thresholds"]:
        assert sum(row[key] for key in ("tn", "fp", "fn", "tp")) == report["rows"]


def test_sensitivity_unchanged_reference():
    assets = load_assets()
    frame = pd.read_csv(Path(__file__).resolve().parents[1] / "data/sample_traffic.csv")
    raw = frame.iloc[0][assets.feature_names].to_dict()
    evidence = sensitivity_evidence(raw, raw, assets)
    assert len(evidence) == 39
    assert np.allclose(evidence["Probability change"], 0)


def test_flow_page_renders(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINEL_USERS_FILE", raising=False)
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "history.db"))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app/main.py")).run(timeout=30)
    app.sidebar.radio[0].set_value("Flow Import").run(timeout=30)
    assert not app.exception
    assert any("Review only" in item.value for item in app.info)
