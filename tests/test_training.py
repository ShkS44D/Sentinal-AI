"""Data integrity and reproducible-training checks."""
import json
from pathlib import Path

from scripts.check_overlap import check_overlap
from scripts.download_data import SHA256
from src.data import (
    COLUMNS, DROP_COLUMNS, MODEL_FEATURES, TEST_PATH, TRAIN_PATH, load_nsl_kdd,
)
from src.report import load_metrics
from src.train import FeaturePreprocessor, train


def test_data_loader_shapes_and_labels():
    assert len(COLUMNS) == 43
    assert len(MODEL_FEATURES) == 39
    training = load_nsl_kdd(TRAIN_PATH)
    testing = load_nsl_kdd(TEST_PATH)
    assert len(training) == 125973
    assert len(testing) == 22544
    assert not set(DROP_COLUMNS) & set(training)
    assert set(training["attack_family"]) == {"Normal", "DoS", "Probe", "R2L", "U2R"}
    assert (training["label_binary"] == (training["attack"] != "normal").astype(int)).all()
    assert (testing["label_binary"] == (testing["attack"] != "normal").astype(int)).all()


def test_preprocessor_uses_fit_rows_only():
    source = load_nsl_kdd(TRAIN_PATH).iloc[:20][MODEL_FEATURES]
    fit_rows = source.iloc[:10].copy()
    held_out = source.iloc[10:11].copy()
    held_out.loc[:, "service"] = "not_seen_in_training"
    transform = FeaturePreprocessor().fit(fit_rows)
    assert "not_seen_in_training" not in transform.encoders_["service"].classes_
    encoded = transform._encode(held_out)
    assert encoded.iloc[0]["service"] == -1
    assert transform.scaler_.n_samples_seen_ == len(fit_rows)
    assert transform.transform(held_out).shape == (1, 39)


def test_small_training_and_report_schema(tmp_path):
    result = train(
        train_path=TRAIN_PATH, test_path=TEST_PATH, output_root=tmp_path,
        train_limit=100, test_limit=40, cv_folds=2, rf_trees=5,
    )
    saved = load_metrics(tmp_path / "reports" / "metrics.json")
    assert saved == result
    assert len(saved["cross_validation"]) == 3
    assert saved["train_rows"] == 100
    metadata = json.loads((tmp_path / "models" / "v1" / "metadata.json").read_text())
    assert metadata["train_rows"] == 100
    assert metadata["random_seed"] == 42
    assert metadata["sklearn_version"]
    assert (tmp_path / "reports" / "figures" / "roc_curve.png").exists()


def test_generated_full_metrics_and_overlap():
    report = load_metrics()
    assert report["train_rows"] == 125973
    assert report["test_rows"] == 22544
    assert sum(report["evaluation"]["confusion_matrix"].values()) == 22544
    assert check_overlap() == (500, 500)
    assert set(SHA256) == {"KDDTrain+.txt", "KDDTest+.txt"}
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert f"{report['evaluation']['f1']:.2%}" in readme
    assert f"{report['evaluation']['recall']:.2%}" in readme
