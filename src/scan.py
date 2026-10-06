"""Validation, vectorized scanning, thresholding and exports."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path

import numpy as np
import pandas as pd

from src.data import CATEGORICAL, COLUMNS, FAMILY_BY_ATTACK, MODEL_FEATURES
from src.model import Assets
from src.prediction import preprocess

MAX_BYTES = 30 * 1024 * 1024
MAX_ROWS = 100_000
RATE_COLUMNS = tuple(name for name in MODEL_FEATURES if name.endswith("_rate"))
BOOLEAN_COLUMNS = ("land", "logged_in", "root_shell", "is_guest_login")
DISPLAY_COLUMNS = ("duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes")


@dataclass
class ValidatedUpload:
    features: pd.DataFrame | None = None
    labels: pd.Series | None = None
    families: pd.Series | None = None
    mode: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def read_upload(content: bytes, filename: str) -> pd.DataFrame:
    """Read a headed CSV or headerless original NSL-KDD text file."""
    if not content or not content.strip():
        raise ValueError("The uploaded file is empty.")
    if len(content) > MAX_BYTES:
        raise ValueError(f"File is too large. Maximum upload size is {MAX_BYTES // 1024 // 1024} MB.")
    suffix = Path(filename).suffix.lower()
    if suffix not in {".csv", ".txt"}:
        raise ValueError("Upload a .csv or original NSL-KDD .txt file.")
    try:
        first = content.splitlines()[0].decode("utf-8-sig")
        if ";" in first and first.count(";") > first.count(","):
            raise ValueError("Wrong delimiter: this file appears to use semicolons. Use commas.")
        if suffix == ".txt":
            if len(first.split(",")) != len(COLUMNS):
                raise ValueError("NSL-KDD .txt rows must have exactly 43 comma-separated fields.")
            frame = pd.read_csv(BytesIO(content), header=None, names=COLUMNS)
        else:
            frame = pd.read_csv(BytesIO(content), encoding="utf-8-sig")
    except (UnicodeDecodeError, pd.errors.ParserError) as exc:
        raise ValueError(f"Cannot parse upload as UTF-8 comma-separated data: {exc}") from exc
    if frame.empty:
        raise ValueError("The uploaded file has no data rows.")
    if len(frame) > MAX_ROWS:
        raise ValueError(f"Too many rows: {len(frame):,}. Maximum is {MAX_ROWS:,}.")
    return frame


def validate_upload(frame: pd.DataFrame, assets: Assets, training_ranges=None) -> ValidatedUpload:
    """Collect specific errors; accept raw names or training encoder integers."""
    result = ValidatedUpload()
    if frame.empty:
        result.errors.append("The uploaded file has no data rows.")
        return result
    if len(frame) > MAX_ROWS:
        result.errors.append(f"Too many rows: {len(frame):,}. Maximum is {MAX_ROWS:,}.")
        return result
    if frame.columns.duplicated().any():
        result.errors.append("Duplicate column names are not allowed.")
    missing = [name for name in assets.feature_names if name not in frame]
    if missing:
        result.errors.append("Missing required columns: " + ", ".join(missing))
        return result
    features = frame[assets.feature_names].copy()
    modes = set()
    for column, encoder in assets.encoders.items():
        values = features[column]
        if values.isna().any():
            result.errors.append(f"{column}: {int(values.isna().sum())} missing value(s).")
            continue
        normalized = values.astype(str).str.strip()
        is_integer = normalized.str.fullmatch(r"[+-]?\d+")
        if is_integer.any():
            modes.add("encoded integers")
            codes = pd.to_numeric(normalized[is_integer], errors="coerce")
            bad = codes.isna() | (codes < 0) | (codes >= len(encoder.classes_))
            if bad.any():
                examples = normalized[is_integer][bad].unique()[:3]
                result.errors.append(
                    f"{column}: invalid encoded value(s) {', '.join(examples)}; "
                    f"expected integers 0–{len(encoder.classes_) - 1}."
                )
            else:
                features.loc[is_integer, column] = encoder.inverse_transform(codes.astype(int))
        if (~is_integer).any():
            modes.add("raw text")
            unknown = sorted(set(normalized[~is_integer]) - set(encoder.classes_))
            if unknown:
                result.errors.append(
                    f"{column}: unknown category value(s): {', '.join(unknown[:5])}."
                )
            features.loc[~is_integer, column] = normalized[~is_integer]
    result.mode = " and ".join(sorted(modes)) if modes else "unknown"
    for column in assets.feature_names:
        if column in CATEGORICAL:
            continue
        raw = features[column]
        numeric = pd.to_numeric(raw, errors="coerce")
        invalid = numeric.isna() | ~np.isfinite(numeric)
        if invalid.any():
            result.errors.append(f"{column}: {int(invalid.sum())} missing or non-numeric value(s).")
            continue
        if (numeric < 0).any():
            result.errors.append(f"{column}: negative values are not valid for NSL-KDD features.")
        if column in RATE_COLUMNS and (numeric > 1).any():
            result.errors.append(f"{column}: rates must be between 0 and 1.")
        if column in BOOLEAN_COLUMNS and (~numeric.isin([0, 1])).any():
            result.errors.append(f"{column}: expected only 0 or 1.")
        if column not in RATE_COLUMNS and (numeric % 1 != 0).any():
            result.errors.append(f"{column}: expected whole numbers.")
        if training_ranges and column in training_ranges:
            low, high = training_ranges[column]
            outside = int(((numeric < low) | (numeric > high)).sum())
            if outside:
                result.warnings.append(
                    f"{column}: {outside} value(s) outside the training range {low:g}–{high:g}; "
                    "scanning will continue."
                )
        features[column] = numeric
    label_column = next((name for name in ("label_binary", "class", "attack") if name in frame), None)
    if "attack" in frame:
        names = frame["attack"].astype(str).str.rstrip(".").str.lower()
        unknown_attacks = sorted(set(names) - set(FAMILY_BY_ATTACK))
        if unknown_attacks:
            result.errors.append("attack: unknown label(s): " + ", ".join(unknown_attacks[:5]))
        else:
            result.families = names.map(FAMILY_BY_ATTACK)
    if label_column:
        labels = frame[label_column]
        if label_column == "attack":
            normalized = labels.astype(str).str.rstrip(".").str.lower()
            if result.families is not None:
                result.labels = (normalized != "normal").astype(int)
        else:
            numeric = pd.to_numeric(labels, errors="coerce")
            if numeric.isna().any() or (~numeric.isin([0, 1])).any():
                result.errors.append(f"{label_column}: labels must be 0 (normal) or 1 (anomaly).")
            else:
                result.labels = numeric.astype(int)
    if not result.errors:
        result.features = features.reset_index(drop=True)
        if result.labels is not None:
            result.labels = result.labels.reset_index(drop=True)
        if result.families is not None:
            result.families = result.families.reset_index(drop=True)
    return result


def scan_batch(features: pd.DataFrame, assets: Assets, progress=None, chunk_size=10_000):
    """Predict anomaly probabilities in vectorized chunks for bounded memory."""
    probabilities = np.empty(len(features), dtype=float)
    for start in range(0, len(features), chunk_size):
        end = min(start + chunk_size, len(features))
        prepared = preprocess(features.iloc[start:end], assets)
        probabilities[start:end] = assets.model.predict_proba(prepared)[:, 1]
        if progress is not None:
            progress(end / len(features))
    return probabilities


def classify(probabilities, threshold=0.5, medium_at=0.5, high_at=0.8):
    if not 0 <= threshold <= 1 or not 0 <= medium_at < high_at <= 1:
        raise ValueError("Threshold and severity bands must be within 0–1, with Medium below High.")
    values = np.asarray(probabilities, dtype=float)
    prediction = np.where(values >= threshold, "Anomaly", "Normal")
    severity = np.where(values >= high_at, "High", np.where(values >= medium_at, "Medium", "Low"))
    return prediction, severity


def labeled_metrics(prediction, labels):
    actual = np.asarray(labels, dtype=int)
    predicted = np.asarray(prediction) == "Anomaly"
    tp = int(np.sum(predicted & (actual == 1)))
    fp = int(np.sum(predicted & (actual == 0)))
    fn = int(np.sum(~predicted & (actual == 1)))
    tn = int(np.sum(~predicted & (actual == 0)))
    return {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positives": fp,
        "true_positives": tp,
        "false_negatives": fn,
        "true_negatives": tn,
    }


def results_table(features, probabilities, threshold, medium_at, high_at, labels=None):
    prediction, severity = classify(probabilities, threshold, medium_at, high_at)
    table = features[list(DISPLAY_COLUMNS)].reset_index(drop=True).copy()
    table.insert(0, "row", np.arange(1, len(table) + 1))
    table["prediction"] = prediction
    table["anomaly_probability"] = np.asarray(probabilities)
    table["severity"] = severity
    if labels is not None:
        table["actual_label"] = np.where(np.asarray(labels) == 1, "Anomaly", "Normal")
    return table


def export_csv(table):
    return table.to_csv(index=False).encode("utf-8-sig")


def export_html(table, threshold, medium_at, high_at, model_version="v1", timestamp=None,
                metrics=None):
    """Make a standalone one-page summary without embedding uploaded rows."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    counts = table["prediction"].value_counts()
    severities = table["severity"].value_counts()
    lines = [
        "<!doctype html><html lang='en'><meta charset='utf-8'>",
        "<title>Sentinel IDS scan summary</title>",
        "<style>body{font:16px system-ui;max-width:720px;margin:40px auto;color:#18212d}"
        "h1{color:#087c9e}table{border-collapse:collapse;width:100%}"
        "td,th{padding:10px;border-bottom:1px solid #ccd5de;text-align:left}</style>",
        "<h1>Sentinel IDS · Scan summary</h1>",
        f"<p>Model version: {escape(model_version)} · Generated: "
        f"{escape(timestamp.isoformat())}</p>",
        f"<p>Decision threshold: {threshold:.2f} · Medium from {medium_at:.2f} · "
        f"High from {high_at:.2f}</p>",
        "<table><tr><th>Measure</th><th>Count</th></tr>",
        f"<tr><td>Scanned rows</td><td>{len(table):,}</td></tr>",
        f"<tr><td>Predicted anomalies</td><td>{counts.get('Anomaly', 0):,}</td></tr>",
        f"<tr><td>Predicted normal</td><td>{counts.get('Normal', 0):,}</td></tr>",
    ]
    lines.extend(
        f"<tr><td>{name} severity</td><td>{severities.get(name, 0):,}</td></tr>"
        for name in ("Low", "Medium", "High")
    )
    if metrics is not None:
        lines.extend([
            f"<tr><td>Precision (uploaded labels)</td><td>{metrics['precision']:.1%}</td></tr>",
            f"<tr><td>Recall (uploaded labels)</td><td>{metrics['recall']:.1%}</td></tr>",
            f"<tr><td>False positives</td><td>{metrics['false_positives']:,}</td></tr>",
        ])
    lines.extend(["</table>", "<p>Predictions are from an NSL-KDD benchmark model, not live network monitoring.</p>", "</html>"])
    return "\n".join(lines).encode("utf-8")
