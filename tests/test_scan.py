"""Phase 3 upload, classification and export behavior."""

from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.data import MODEL_FEATURES, TEST_PATH, load_nsl_kdd
from src.feature_info import GROUPS, HINTS, training_statistics
from src.model import load_assets
from src.prediction import preprocess
from src.scan import (
    MAX_BYTES, MAX_ROWS, classify, export_csv, export_html, labeled_metrics,
    read_upload, results_table, scan_batch, validate_upload,
)
from app.pages.batch import _template_csv

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "sample_traffic.csv"


@pytest.fixture(scope="module")
def assets():
    return load_assets()


def test_sample_upload_end_to_end_and_provenance(assets):
    frame = read_upload(SAMPLE.read_bytes(), SAMPLE.name)
    checked = validate_upload(frame, assets)
    assert not checked.errors
    assert checked.mode == "raw text"
    assert checked.labels is not None
    probabilities = scan_batch(checked.features, assets, chunk_size=7)
    by_row = np.array([
        assets.model.predict_proba(preprocess(row.to_dict(), assets))[0, 1]
        for _, row in checked.features.iterrows()
    ])
    np.testing.assert_allclose(probabilities, by_row)
    assert len(probabilities) == 20
    test_rows = load_nsl_kdd(TEST_PATH)[MODEL_FEATURES + ["label_binary"]]
    assert len(frame.merge(test_rows.drop_duplicates(), on=MODEL_FEATURES + ["label_binary"])) == 20


def test_encoded_and_mixed_category_inputs(assets):
    frame = read_upload(SAMPLE.read_bytes(), SAMPLE.name)
    for name, encoder in assets.encoders.items():
        frame[name] = encoder.transform(frame[name])
    encoded = validate_upload(frame, assets)
    assert not encoded.errors
    assert encoded.mode == "encoded integers"
    assert encoded.features["protocol_type"].iloc[0] == "tcp"
    frame.loc[0, "protocol_type"] = "tcp"
    mixed = validate_upload(frame, assets)
    assert not mixed.errors
    assert mixed.mode == "encoded integers and raw text"


def test_original_txt_and_unlabeled_csv(assets):
    first_rows = b"\n".join(TEST_PATH.read_bytes().splitlines()[:3]) + b"\n"
    original = validate_upload(read_upload(first_rows, "KDDTest+.txt"), assets)
    assert not original.errors
    assert original.labels is not None
    assert original.families is not None
    unlabelled = read_upload(SAMPLE.read_bytes(), SAMPLE.name).drop(columns="label_binary")
    checked = validate_upload(unlabelled, assets)
    assert not checked.errors
    assert checked.labels is None
    assert _template_csv().decode().strip().split(",") == MODEL_FEATURES


@pytest.mark.parametrize(
    ("content", "name", "message"),
    [
        (b"", "bad.csv", "empty"),
        (b"a;b\n1;2\n", "bad.csv", "delimiter"),
        (b"x,y\n1,2\n", "bad.txt", "43"),
        (b"x\n1\n", "bad.json", ".csv"),
        (b"x,y\n1,2\n", "bad.csv", None),
    ],
)
def test_file_parsing_errors(content, name, message):
    if message is None:
        assert len(read_upload(content, name)) == 1
    else:
        with pytest.raises(ValueError, match=message):
            read_upload(content, name)


def test_huge_upload_rejected():
    with pytest.raises(ValueError, match="too large"):
        read_upload(b"x" * (MAX_BYTES + 1), "huge.csv")


def test_validation_error_list(assets):
    original = read_upload(SAMPLE.read_bytes(), SAMPLE.name)
    missing = validate_upload(original.drop(columns=["duration", "service"]), assets)
    assert "duration" in missing.errors[0]
    assert "service" in missing.errors[0]
    broken = original.copy()
    broken.loc[0, "protocol_type"] = "not_a_protocol"
    broken.loc[1, "service"] = 9999
    broken.loc[2, "src_bytes"] = "abc"
    broken.loc[3, "serror_rate"] = 2.0
    broken.loc[4, "dst_bytes"] = -1
    broken.loc[5, "duration"] = None
    issues = validate_upload(broken, assets)
    joined = " ".join(issues.errors)
    for expected in ("unknown category", "invalid encoded", "non-numeric", "rates", "negative", "missing"):
        assert expected in joined
    assert issues.features is None
    with pytest.raises(ValueError, match="Too many rows"):
        read_upload(pd.concat([original] * (MAX_ROWS // len(original) + 1)).to_csv(index=False).encode(), "many.csv")


def test_outside_training_range_is_explicit_warning(assets):
    frame = read_upload(SAMPLE.read_bytes(), SAMPLE.name)
    observed = training_statistics()["src_bytes"]
    frame.loc[0, "src_bytes"] = int(observed["max"]) + 1
    checked = validate_upload(
        frame, assets, {"src_bytes": (observed["min"], observed["max"])},
    )
    assert not checked.errors
    assert any("src_bytes" in warning for warning in checked.warnings)


def test_threshold_severity_and_labeled_metrics():
    probabilities = np.array([0.2, 0.49, 0.6, 0.9])
    predicted, severity = classify(probabilities, 0.5, 0.5, 0.8)
    assert predicted.tolist() == ["Normal", "Normal", "Anomaly", "Anomaly"]
    assert severity.tolist() == ["Low", "Low", "Medium", "High"]
    lowered, _ = classify(probabilities, 0.4, 0.5, 0.8)
    assert lowered.tolist() == ["Normal", "Anomaly", "Anomaly", "Anomaly"]
    metrics = labeled_metrics(predicted, [0, 1, 1, 0])
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["false_positives"] == 1
    with pytest.raises(ValueError, match="severity bands"):
        classify(probabilities, 0.5, 0.8, 0.5)


def test_exports_include_counts_and_settings(assets):
    checked = validate_upload(read_upload(SAMPLE.read_bytes(), SAMPLE.name), assets)
    probabilities = scan_batch(checked.features, assets)
    table = results_table(checked.features, probabilities, 0.5, 0.5, 0.8, checked.labels)
    csv_content = export_csv(table).decode("utf-8-sig")
    assert "anomaly_probability" in csv_content
    assert "actual_label" in csv_content
    assert len(pd.read_csv(StringIO(csv_content))) == 20
    metrics = labeled_metrics(table["prediction"], checked.labels)
    html = export_html(
        table, 0.5, 0.5, 0.8, model_version="v1",
        timestamp=datetime(2026, 10, 6, tzinfo=timezone.utc), metrics=metrics,
    ).decode()
    assert "Model version: v1" in html
    assert "2026-10-06" in html
    assert "Scanned rows</td><td>20" in html
    assert "Decision threshold: 0.50" in html
    assert "False positives" in html


def test_manual_feature_metadata_covers_every_feature():
    assert [name for names in GROUPS.values() for name in names] == MODEL_FEATURES
    assert set(HINTS) == set(MODEL_FEATURES)
    stats = training_statistics()
    assert set(stats) == set(MODEL_FEATURES) - set(load_assets().encoders)
    assert all(item["min"] <= item["default"] <= item["max"] for item in stats.values())
