"""SQLite persistence and analyst queries for Sentinel IDS."""

from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import sqlite3
from zipfile import ZIP_DEFLATED, ZipFile

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "sentinel.db"
MODEL_VERSION = "v1"
STATUSES = ("New", "Investigating", "Confirmed", "False Positive", "Resolved")
OPEN_STATUSES = ("New", "Investigating", "Confirmed")
TABLES = ("scans", "detections", "status_history", "audit_events")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connection(path=DEFAULT_DB):
    if Path(path) == DEFAULT_DB and os.environ.get("SENTINEL_DB_PATH"):
        path = os.environ["SENTINEL_DB_PATH"]
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db(path=DEFAULT_DB):
    """Create v1 schema; reject unknown newer schemas."""
    with connection(path) as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > 1:
            raise RuntimeError(f"Database schema version {version} is newer than this app supports")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
            source TEXT NOT NULL CHECK(source IN ('manual','batch')),
            filename TEXT, model_version TEXT NOT NULL,
            threshold REAL NOT NULL, medium_at REAL NOT NULL DEFAULT 0.5,
            high_at REAL NOT NULL DEFAULT 0.8, is_demo INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL, features_json TEXT NOT NULL,
            prediction TEXT NOT NULL CHECK(prediction IN ('Normal','Anomaly')),
            probability REAL NOT NULL, severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New', analyst_note TEXT NOT NULL DEFAULT '',
            family TEXT
        );
        CREATE TABLE IF NOT EXISTS status_history (
            id INTEGER PRIMARY KEY, detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL, old_status TEXT, new_status TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL, details TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_detection_scan ON detections(scan_id);
        CREATE INDEX IF NOT EXISTS ix_detection_prediction ON detections(prediction, status, severity);
        CREATE INDEX IF NOT EXISTS ix_detection_time ON detections(timestamp);
        CREATE INDEX IF NOT EXISTS ix_status_history_detection ON status_history(detection_id);
        """)
        db.execute("PRAGMA user_version = 1")


def save_scan(records, *, source, filename=None, model_version=MODEL_VERSION,
              threshold=0.5, medium_at=0.5, high_at=0.8, is_demo=False,
              path=DEFAULT_DB):
    """Save one scan and all of its detections atomically."""
    if source not in {"manual", "batch"}:
        raise ValueError("Scan source must be manual or batch")
    if not 0 <= threshold <= 1 or not 0 <= medium_at < high_at <= 1:
        raise ValueError("Invalid decision threshold or severity bands")
    init_db(path)
    timestamp = utc_now()
    with connection(path) as db:
        scan_id = db.execute(
            "INSERT INTO scans(timestamp,source,filename,model_version,threshold,medium_at,high_at,is_demo) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (timestamp, source, filename, model_version, threshold, medium_at, high_at, int(is_demo)),
        ).lastrowid
        payload = []
        count = 0
        for record in records:
            probability = float(record["probability"])
            if not 0 <= probability <= 1:
                raise ValueError("Probability must be within 0–1")
            payload.append((
                scan_id, timestamp, json.dumps(record["features"], default=str),
                "Anomaly" if probability >= threshold else "Normal", probability,
                "High" if probability >= high_at else "Medium" if probability >= medium_at else "Low",
                "New", "", record.get("family"),
            ))
            count += 1
            if len(payload) >= 1000:
                db.executemany(
                    "INSERT INTO detections(scan_id,timestamp,features_json,prediction,probability,"
                    "severity,status,analyst_note,family) VALUES(?,?,?,?,?,?,?,?,?)", payload,
                )
                payload.clear()
        if not count:
            raise ValueError("Cannot save an empty scan")
        if payload:
            db.executemany(
                "INSERT INTO detections(scan_id,timestamp,features_json,prediction,probability,"
                "severity,status,analyst_note,family) VALUES(?,?,?,?,?,?,?,?,?)", payload,
            )
        db.execute(
            "INSERT INTO audit_events(timestamp,event_type,details) VALUES(?,?,?)",
            (timestamp, "scan_created", json.dumps({"scan_id": scan_id, "rows": count,
                                                    "source": source, "is_demo": bool(is_demo)})),
        )
    return scan_id


def frame_records(features, probabilities, families=None):
    """Yield storage records from a validated frame without making a large list."""
    columns = list(features.columns)
    for index, row in enumerate(features.itertuples(index=False, name=None)):
        yield {
            "features": dict(zip(columns, row, strict=True)),
            "probability": float(probabilities[index]),
            "family": None if families is None else str(families.iloc[index]),
        }


def reclassify_scan(scan_id, threshold, medium_at=0.5, high_at=0.8, path=DEFAULT_DB):
    """Persist live threshold and severity adjustments without rescanning."""
    if not 0 <= threshold <= 1 or not 0 <= medium_at < high_at <= 1:
        raise ValueError("Invalid decision threshold or severity bands")
    init_db(path)
    with connection(path) as db:
        scan = db.execute("SELECT threshold,medium_at,high_at FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise ValueError(f"Scan {scan_id} does not exist")
        if tuple(scan) == (threshold, medium_at, high_at):
            return
        db.execute(
            "UPDATE scans SET threshold=?,medium_at=?,high_at=? WHERE id=?",
            (threshold, medium_at, high_at, scan_id),
        )
        db.execute(
            "UPDATE detections SET prediction=CASE WHEN probability>=? THEN 'Anomaly' ELSE 'Normal' END, "
            "severity=CASE WHEN probability>=? THEN 'High' WHEN probability>=? THEN 'Medium' ELSE 'Low' END "
            "WHERE scan_id=?", (threshold, high_at, medium_at, scan_id),
        )
        db.execute(
            "INSERT INTO audit_events(timestamp,event_type,details) VALUES(?,?,?)",
            (utc_now(), "threshold_changed", json.dumps({"scan_id": scan_id,
                "old_threshold": scan["threshold"], "threshold": threshold,
                "medium_at": medium_at, "high_at": high_at})),
        )


def get_detection(detection_id, path=DEFAULT_DB):
    init_db(path)
    with connection(path) as db:
        row = db.execute(
            "SELECT d.*, s.source,s.filename,s.model_version,s.is_demo,s.threshold "
            "FROM detections d JOIN scans s ON d.scan_id=s.id WHERE d.id=?", (detection_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["features"] = json.loads(result.pop("features_json"))
        return result


def status_timeline(detection_id, path=DEFAULT_DB):
    init_db(path)
    with connection(path) as db:
        created = db.execute(
            "SELECT timestamp FROM detections WHERE id=?", (detection_id,)
        ).fetchone()
        if created is None:
            return []
        entries = [{"timestamp": created["timestamp"], "old_status": None,
                    "new_status": "New", "note": "Alert created"}]
        entries.extend(dict(row) for row in db.execute(
            "SELECT timestamp,old_status,new_status,note FROM status_history "
            "WHERE detection_id=? ORDER BY id", (detection_id,)
        ))
        return entries


def update_alerts(ids, *, status=None, note=None, path=DEFAULT_DB):
    """Apply one status or note action to multiple anomaly alerts."""
    if status is None and not (note or "").strip():
        raise ValueError("Choose a status or enter a note")
    if status is not None and status not in STATUSES:
        raise ValueError(f"Invalid status: {status}")
    ids = sorted({int(value) for value in ids})
    if not ids:
        raise ValueError("Select at least one alert")
    init_db(path)
    changed = 0
    with connection(path) as db:
        for detection_id in ids:
            row = db.execute(
                "SELECT status,analyst_note FROM detections WHERE id=? AND prediction='Anomaly'",
                (detection_id,),
            ).fetchone()
            if row is None:
                continue
            new_status = status or row["status"]
            supplied_note = (note or "").strip()
            new_note = row["analyst_note"]
            if supplied_note:
                new_note = f"{new_note}\n{supplied_note}".strip()
            if new_status == row["status"] and new_note == row["analyst_note"]:
                continue
            db.execute(
                "UPDATE detections SET status=?,analyst_note=? WHERE id=?",
                (new_status, new_note, detection_id),
            )
            timestamp = utc_now()
            if new_status != row["status"]:
                db.execute(
                    "INSERT INTO status_history(detection_id,timestamp,old_status,new_status,note) "
                    "VALUES(?,?,?,?,?)",
                    (detection_id, timestamp, row["status"], new_status, supplied_note),
                )
            db.execute(
                "INSERT INTO audit_events(timestamp,event_type,details) VALUES(?,?,?)",
                (timestamp, "status_changed" if new_status != row["status"] else "note_added",
                 json.dumps({"detection_id": detection_id, "old_status": row["status"],
                             "new_status": new_status, "note": supplied_note})),
            )
            changed += 1
    return changed


SORTS = {
    "Newest": "d.timestamp DESC, d.id DESC",
    "Oldest": "d.timestamp ASC, d.id ASC",
    "Highest probability": "d.probability DESC, d.id DESC",
    "Lowest probability": "d.probability ASC, d.id ASC",
    "Severity": "CASE d.severity WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, d.id DESC",
}


def query_alerts(*, search="", severities=(), statuses=(), start_date=None, end_date=None,
                 protocols=(), services=(), sort="Newest", page=1, page_size=25,
                 path=DEFAULT_DB):
    """Return filtered anomaly alerts and total count with safe pagination."""
    if sort not in SORTS:
        raise ValueError(f"Unsupported alert sort: {sort}")
    if page < 1 or page_size not in {25, 50, 100, 1000}:
        raise ValueError("Invalid alert page or page size")
    init_db(path)
    where = ["d.prediction='Anomaly'"]
    params = []
    if search.strip():
        where.append("(CAST(d.id AS TEXT) LIKE ? OR d.features_json LIKE ? OR d.analyst_note LIKE ?)")
        params.extend([f"%{search.strip()}%"] * 3)
    for column, values in (("d.severity", severities), ("d.status", statuses),
                           ("json_extract(d.features_json,'$.protocol_type')", protocols),
                           ("json_extract(d.features_json,'$.service')", services)):
        if values:
            where.append(f"{column} IN ({','.join('?' for _ in values)})")
            params.extend(values)
    if start_date:
        where.append("substr(d.timestamp,1,10)>=?")
        params.append(str(start_date))
    if end_date:
        where.append("substr(d.timestamp,1,10)<=?")
        params.append(str(end_date))
    clause = " AND ".join(where)
    base = "FROM detections d JOIN scans s ON d.scan_id=s.id WHERE " + clause
    with connection(path) as db:
        total = db.execute("SELECT COUNT(*) " + base, params).fetchone()[0]
        query = (
            "SELECT d.id,d.scan_id,d.timestamp,d.prediction,d.probability,d.severity,"
            "d.status,d.analyst_note,d.family,s.source,s.filename,s.is_demo,"
            "json_extract(d.features_json,'$.protocol_type') AS protocol_type,"
            "json_extract(d.features_json,'$.service') AS service "
            + base + " ORDER BY " + SORTS[sort] + " LIMIT ? OFFSET ?"
        )
        rows = [dict(row) for row in db.execute(
            query, [*params, page_size, (page - 1) * page_size]
        )]
    return rows, total


def export_alerts_csv(*, path=DEFAULT_DB, **filters):
    """Export every alert matching the UI filters, across all pages."""
    page = 1
    rows = []
    while True:
        batch, total = query_alerts(page=page, page_size=1000, path=path, **filters)
        rows.extend(batch)
        if len(rows) >= total or not batch:
            break
        page += 1
    columns = ("id", "scan_id", "timestamp", "probability", "severity", "status",
               "protocol_type", "service", "family", "analyst_note", "source", "filename", "is_demo")
    return pd.DataFrame(rows, columns=columns).to_csv(index=False).encode("utf-8-sig")


def alert_filter_options(path=DEFAULT_DB):
    init_db(path)
    with connection(path) as db:
        values = {}
        for key in ("protocol_type", "service"):
            values[key] = [row[0] for row in db.execute(
                f"SELECT DISTINCT json_extract(features_json,'$.{key}') FROM detections "
                "WHERE prediction='Anomaly' ORDER BY 1"
            ) if row[0] is not None]
        return values


def dashboard_data(path=DEFAULT_DB):
    """Aggregate only persisted scans and detections."""
    init_db(path)
    with connection(path) as db:
        scans = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        demo_scans = db.execute("SELECT COUNT(*) FROM scans WHERE is_demo=1").fetchone()[0]
        detections = db.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        demo_detections = db.execute(
            "SELECT COUNT(*) FROM detections d JOIN scans s ON d.scan_id=s.id WHERE s.is_demo=1"
        ).fetchone()[0]
        anomalies = db.execute(
            "SELECT COUNT(*) FROM detections WHERE prediction='Anomaly'"
        ).fetchone()[0]
        open_by_status = {row[0]: row[1] for row in db.execute(
            "SELECT status,COUNT(*) FROM detections WHERE prediction='Anomaly' "
            "AND status IN ('New','Investigating','Confirmed') GROUP BY status"
        )}
        open_by_severity = {row[0]: row[1] for row in db.execute(
            "SELECT severity,COUNT(*) FROM detections WHERE prediction='Anomaly' "
            "AND status IN ('New','Investigating','Confirmed') GROUP BY severity"
        )}
        over_time = [dict(row) for row in db.execute(
            "SELECT substr(timestamp,1,10) AS day, COUNT(*) AS detections,"
            "SUM(CASE WHEN prediction='Anomaly' THEN 1 ELSE 0 END) AS anomalies "
            "FROM detections GROUP BY day ORDER BY day"
        )]
        top = {}
        for key in ("service", "protocol_type"):
            top[key] = [dict(row) for row in db.execute(
                f"SELECT json_extract(features_json,'$.{key}') AS name,COUNT(*) AS count "
                "FROM detections WHERE prediction='Anomaly' GROUP BY name "
                "ORDER BY count DESC,name LIMIT 10"
            )]
        recent = [dict(row) for row in db.execute(
            "SELECT a.timestamp,a.event_type,a.details FROM audit_events a "
            "ORDER BY a.id DESC LIMIT 10"
        )]
    return {
        "scans": scans, "demo_scans": demo_scans,
        "detections": detections, "demo_detections": demo_detections,
        "anomalies": anomalies,
        "anomaly_rate": anomalies / detections if detections else 0.0,
        "open_by_status": open_by_status, "open_by_severity": open_by_severity,
        "over_time": over_time, "top_services": top["service"],
        "top_protocols": top["protocol_type"], "recent": recent,
    }


def database_size(path=DEFAULT_DB):
    if Path(path) == DEFAULT_DB and os.environ.get("SENTINEL_DB_PATH"):
        path = os.environ["SENTINEL_DB_PATH"]
    file = Path(path)
    return file.stat().st_size if file.exists() else 0


def _delete_scans(db, scan_ids, event_type):
    if not scan_ids:
        return 0
    count = db.execute(
        f"SELECT COUNT(*) FROM detections WHERE scan_id IN ({','.join('?' for _ in scan_ids)})",
        scan_ids,
    ).fetchone()[0]
    db.executemany("DELETE FROM scans WHERE id=?", [(scan_id,) for scan_id in scan_ids])
    db.execute(
        "INSERT INTO audit_events(timestamp,event_type,details) VALUES(?,?,?)",
        (utc_now(), event_type, json.dumps({"scan_count": len(scan_ids), "detection_count": count})),
    )
    return count


def delete_demo_data(path=DEFAULT_DB):
    init_db(path)
    with connection(path) as db:
        ids = [row[0] for row in db.execute("SELECT id FROM scans WHERE is_demo=1")]
        return _delete_scans(db, ids, "demo_data_deleted")


def delete_all_data(path=DEFAULT_DB):
    """Clear scan data and prior audit history, retaining a deletion receipt."""
    init_db(path)
    with connection(path) as db:
        scan_count = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        detection_count = db.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        db.execute("DELETE FROM scans")
        db.execute("DELETE FROM audit_events")
        db.execute(
            "INSERT INTO audit_events(timestamp,event_type,details) VALUES(?,?,?)",
            (utc_now(), "all_data_deleted", json.dumps({"scan_count": scan_count,
                                                    "detection_count": detection_count})),
        )
    return scan_count, detection_count


def audit_events(path=DEFAULT_DB):
    init_db(path)
    with connection(path) as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM audit_events ORDER BY id DESC"
        )]


def export_database_csv(path=DEFAULT_DB):
    """Return a ZIP containing a CSV for each database table."""
    init_db(path)
    output = BytesIO()
    with connection(path) as db, ZipFile(output, "w", ZIP_DEFLATED) as bundle:
        for table in TABLES:
            frame = pd.read_sql_query(f"SELECT * FROM {table}", db)
            bundle.writestr(f"{table}.csv", frame.to_csv(index=False))
    return output.getvalue()


def import_database_csv(content, path=DEFAULT_DB):
    """Validate then replace local tables from the exported CSV bundle."""
    if len(content) > 100 * 1024 * 1024:
        raise ValueError("CSV bundle exceeds the 100 MB upload limit")
    init_db(path)
    with ZipFile(BytesIO(content)) as bundle, connection(path) as db:
        expected = {f"{table}.csv" for table in TABLES}
        if set(bundle.namelist()) != expected:
            raise ValueError("CSV bundle must contain scans.csv, detections.csv, status_history.csv and audit_events.csv")
        if sum(bundle.getinfo(name).file_size for name in expected) > 400 * 1024 * 1024:
            raise ValueError("Uncompressed CSV bundle exceeds 400 MB")
        frames = {}
        for table in TABLES:
            name = f"{table}.csv"
            if bundle.getinfo(name).file_size > 250 * 1024 * 1024:
                raise ValueError(f"{name} is too large")
            frame = pd.read_csv(
                StringIO(bundle.read(name).decode("utf-8-sig")),
                dtype=str, keep_default_na=False,
            )
            columns = [row[1] for row in db.execute(f"PRAGMA table_info({table})")]
            if list(frame.columns) != columns:
                raise ValueError(f"{name} has an invalid column schema")
            frames[table] = frame
        for row in frames["scans"].itertuples(index=False):
            if row.source not in {"manual", "batch"} or not 0 <= float(row.threshold) <= 1:
                raise ValueError("scans.csv contains an invalid source or threshold")
        for row in frames["detections"].itertuples(index=False):
            try:
                features = json.loads(row.features_json)
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("detections.csv contains invalid features JSON") from exc
            if not isinstance(features, dict):
                raise ValueError("detections.csv features JSON must be an object")
            if (row.prediction not in {"Normal", "Anomaly"}
                    or row.severity not in {"Low", "Medium", "High"}
                    or row.status not in STATUSES
                    or not 0 <= float(row.probability) <= 1):
                raise ValueError("detections.csv contains an invalid prediction, probability or status")
        for row in frames["status_history"].itertuples(index=False):
            if row.new_status not in STATUSES:
                raise ValueError("status_history.csv contains an invalid status")
        db.execute("DELETE FROM scans")
        db.execute("DELETE FROM audit_events")
        for table in TABLES:
            frame = frames[table]
            if frame.empty:
                continue
            columns = list(frame.columns)
            placeholders = ",".join("?" for _ in columns)
            db.executemany(
                f"INSERT INTO {table}({','.join(columns)}) VALUES({placeholders})",
                frame.itertuples(index=False, name=None),
            )
        db.execute(
            "INSERT INTO audit_events(timestamp,event_type,details) VALUES(?,?,?)",
            (utc_now(), "database_imported", json.dumps({"scan_count": len(frames["scans"])})),
        )
    return len(frames["scans"])


if __name__ == "__main__":
    init_db()
    print(f"Initialized Sentinel database schema v1 at {os.environ.get('SENTINEL_DB_PATH', DEFAULT_DB)}")
