# Local detection history

The app creates `data/sentinel.db` when first opened. This SQLite file is
ignored by Git. Scans and analyst decisions persist across Streamlit restarts
on the same machine. The database uses schema version 1 (`PRAGMA user_version`)
and creates missing tables and indexes automatically.
You can initialize it explicitly with `python -m src.history`.

| Table | Purpose |
|---|---|
| `scans` | Timestamp, manual/batch source, filename, model version, threshold, severity bands, demo tag |
| `detections` | One row per scanned connection, full features JSON, prediction, anomaly probability, severity, status, note, optional dataset family |
| `status_history` | Per-alert status transitions and their timestamps |
| `audit_events` | Scan creation, status changes, notes, threshold changes, imports and deletions |

`New`, `Investigating` and `Confirmed` count as open alerts. `False Positive`
and `Resolved` count as closed. Severity uses user-selected anomaly-probability
bands; it is separate from the anomaly decision threshold. Changing a saved
scan's threshold updates its stored predictions and severity without changing
the model probabilities.

The bundled NSL-KDD sample upload and built-in test examples are marked as
demo scans. Settings can remove only those scans. Dashboard totals include
them, with a visible demo count. `Delete all data` removes scans, detections,
notes and prior audit events, then leaves one deletion receipt.

Settings exports a ZIP bundle containing `scans.csv`, `detections.csv`,
`status_history.csv` and `audit_events.csv`. Import validates those table
headers and replaces the local database in one transaction. Save a backup
before importing over existing work.
