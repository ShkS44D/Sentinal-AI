"""Persistent analyst workflow and dashboard invariants."""

from io import StringIO
import sqlite3
from zipfile import ZIP_DEFLATED, ZipFile
from io import BytesIO

import pandas as pd
import pytest

from src.history import (
    audit_events, dashboard_data, delete_all_data, delete_demo_data,
    export_alerts_csv, export_database_csv, frame_records, get_detection,
    import_database_csv, query_alerts, reclassify_scan, save_scan,
    status_timeline, update_alerts,
)
from src.investigation import explain_alert


def record(probability, service="http", protocol="tcp", family=None):
    return {
        "features": {
            "protocol_type": protocol, "service": service, "flag": "SF",
            "count": 120, "srv_count": 110, "serror_rate": 0.8,
        },
        "probability": probability, "family": family,
    }


def test_crud_persistence_status_timeline_and_audit(tmp_path):
    path = tmp_path / "sentinel.db"
    scan_id = save_scan([record(0.91, family="DoS")], source="manual", path=path)
    assert path.exists()
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    detail = get_detection(1, path)
    assert detail["scan_id"] == scan_id
    assert detail["features"]["service"] == "http"
    assert detail["family"] == "DoS"
    assert update_alerts([1], status="Investigating", note="Checking logs", path=path) == 1
    assert update_alerts([1], status="Confirmed", path=path) == 1
    assert get_detection(1, path)["status"] == "Confirmed"
    assert "Checking logs" in get_detection(1, path)["analyst_note"]
    assert [event["new_status"] for event in status_timeline(1, path)] == [
        "New", "Investigating", "Confirmed",
    ]
    assert [event["event_type"] for event in audit_events(path)][:2] == [
        "status_changed", "status_changed",
    ]


def test_filters_sorting_pagination_bulk_and_csv(tmp_path):
    path = tmp_path / "sentinel.db"
    records = [record(0.6 + index / 1000, service="http" if index % 2 else "ssh",
                      protocol="tcp" if index % 2 else "udp") for index in range(60)]
    save_scan(records, source="batch", filename="traffic.csv", path=path)
    page1, total = query_alerts(path=path, page=1, page_size=25)
    page2, _ = query_alerts(path=path, page=2, page_size=25)
    assert total == 60
    assert len(page1) == len(page2) == 25
    assert {row["id"] for row in page1}.isdisjoint({row["id"] for row in page2})
    filtered, count = query_alerts(
        path=path, protocols=["tcp"], services=["http"],
        severities=["Medium"], sort="Lowest probability",
    )
    assert count == 30
    assert filtered[0]["probability"] < filtered[-1]["probability"]
    assert update_alerts([1, 2], status="False Positive", note="Reviewed", path=path) == 2
    closed, count = query_alerts(path=path, statuses=["False Positive"])
    assert count == 2
    assert all(row["status"] == "False Positive" for row in closed)
    found, count = query_alerts(path=path, search="Reviewed")
    assert count == 2
    today = page1[0]["timestamp"][:10]
    _, count = query_alerts(path=path, start_date=today, end_date=today)
    assert count == 60
    csv_rows = pd.read_csv(StringIO(export_alerts_csv(path=path, statuses=["False Positive"]).decode("utf-8-sig")))
    assert len(csv_rows) == 2


def test_dashboard_aggregates_and_reclassification(tmp_path):
    path = tmp_path / "sentinel.db"
    first = save_scan(
        [record(0.9, "http"), record(0.7, "http"), record(0.1, "ssh")],
        source="batch", path=path,
    )
    save_scan([record(0.95, "ssh", "udp")], source="manual", path=path)
    update_alerts([1], status="Investigating", path=path)
    update_alerts([2], status="Resolved", path=path)
    stats = dashboard_data(path)
    assert (stats["scans"], stats["detections"], stats["anomalies"]) == (2, 4, 3)
    assert stats["anomaly_rate"] == 0.75
    assert stats["open_by_status"] == {"Investigating": 1, "New": 1}
    assert stats["open_by_severity"] == {"High": 2}
    assert stats["top_services"][0] == {"name": "http", "count": 2}
    assert sum(item["detections"] for item in stats["over_time"]) == 4
    reclassify_scan(first, 0.8, path=path)
    assert dashboard_data(path)["anomalies"] == 2
    assert get_detection(2, path)["prediction"] == "Normal"
    assert any(event["event_type"] == "threshold_changed" for event in audit_events(path))


def test_demo_tagging_deletion_and_empty_state(tmp_path):
    path = tmp_path / "sentinel.db"
    assert dashboard_data(path)["scans"] == 0
    save_scan([record(0.9)], source="manual", is_demo=True, path=path)
    save_scan([record(0.8)], source="manual", is_demo=False, path=path)
    assert get_detection(1, path)["is_demo"] == 1
    assert dashboard_data(path)["demo_scans"] == 1
    assert delete_demo_data(path) == 1
    assert dashboard_data(path)["scans"] == 1
    assert get_detection(1, path) is None
    assert get_detection(2, path) is not None
    assert delete_all_data(path) == (1, 1)
    assert dashboard_data(path)["scans"] == 0
    assert audit_events(path)[0]["event_type"] == "all_data_deleted"


def test_database_csv_round_trip_and_reject_bad_schema(tmp_path):
    path = tmp_path / "sentinel.db"
    save_scan([record(0.9), record(0.2)], source="batch", path=path)
    update_alerts([1], status="Confirmed", path=path)
    backup = export_database_csv(path)
    delete_all_data(path)
    assert import_database_csv(backup, path) == 1
    assert dashboard_data(path)["detections"] == 2
    assert get_detection(1, path)["status"] == "Confirmed"
    assert len(status_timeline(1, path)) == 2
    with pytest.raises(ValueError, match="must contain"):
        broken = BytesIO()
        with ZipFile(broken, "w", ZIP_DEFLATED) as bundle:
            bundle.writestr("scans.csv", "id\n1\n")
        import_database_csv(broken.getvalue(), path)
    invalid = BytesIO()
    with ZipFile(BytesIO(backup)) as source, ZipFile(invalid, "w", ZIP_DEFLATED) as target:
        for name in source.namelist():
            if name == "detections.csv":
                frame = pd.read_csv(StringIO(source.read(name).decode()), keep_default_na=False)
                frame.loc[0, "features_json"] = "not-json"
                target.writestr(name, frame.to_csv(index=False))
            else:
                target.writestr(name, source.read(name))
    with pytest.raises(ValueError, match="features JSON"):
        import_database_csv(invalid.getvalue(), path)
    assert dashboard_data(path)["detections"] == 2


def test_frame_records_and_plain_language_summary():
    frame = pd.DataFrame([record(0.9)["features"]])
    rows = list(frame_records(frame, [0.9], pd.Series(["Probe"])))
    assert rows[0]["family"] == "Probe"
    assert rows[0]["features"]["service"] == "http"
    summary = explain_alert(rows[0]["features"])
    assert "serror_rate is 0.80" in summary
    assert "count is 120" in summary
