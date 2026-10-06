"""Reproduce Sentinel IDS training and official NSL-KDD test evaluation."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    PrecisionRecallDisplay,
    RocCurveDisplay,
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

from src.data import CATEGORICAL, MODEL_FEATURES, TEST_PATH, TRAIN_PATH, load_nsl_kdd

SEED = 42
ROOT = Path(__file__).resolve().parents[1]


class FeaturePreprocessor(BaseEstimator, TransformerMixin):
    """Fit encoders and scaler inside each CV training fold."""

    def fit(self, features, target=None):
        self.feature_names_ = list(MODEL_FEATURES)
        self.encoders_ = {}
        for column in CATEGORICAL:
            encoder = LabelEncoder().fit(features[column].astype(str))
            self.encoders_[column] = encoder
        self.scaler_ = MinMaxScaler().fit(self._encode(features))
        return self

    def _encode(self, features):
        frame = features[self.feature_names_].copy()
        for column, encoder in self.encoders_.items():
            mapping = {name: index for index, name in enumerate(encoder.classes_)}
            frame[column] = frame[column].astype(str).map(mapping).fillna(-1).astype(int)
        return frame.apply(pd.to_numeric, errors="raise")

    def transform(self, features):
        return self.scaler_.transform(self._encode(features))


def _models(rf_trees):
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=rf_trees, random_state=SEED, n_jobs=-1
        ),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=SEED),
        "Histogram Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=80, random_state=SEED
        ),
    }


def _git_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _save_figures(y_true, prediction, probability, directory):
    directory.mkdir(parents=True, exist_ok=True)
    display = ConfusionMatrixDisplay.from_predictions(
        y_true, prediction, display_labels=["Normal", "Anomaly"], cmap="Blues"
    )
    display.figure_.savefig(directory / "confusion_matrix.png", dpi=150, bbox_inches="tight")
    plt.close(display.figure_)
    display = RocCurveDisplay.from_predictions(y_true, probability)
    display.figure_.savefig(directory / "roc_curve.png", dpi=150, bbox_inches="tight")
    plt.close(display.figure_)
    display = PrecisionRecallDisplay.from_predictions(y_true, probability)
    display.figure_.savefig(directory / "pr_curve.png", dpi=150, bbox_inches="tight")
    plt.close(display.figure_)


def _update_readme(metrics, root):
    path = root / "README.md"
    if not path.exists():
        return
    content = path.read_text(encoding="utf-8")
    begin = "<!-- METRICS:START -->"
    end = "<!-- METRICS:END -->"
    if begin not in content or end not in content:
        return
    result = metrics["evaluation"]
    cv_rf = next(row for row in metrics["cross_validation"] if row["model"] == "Random Forest")
    block = "\n".join([
        begin,
        f"Random Forest on **NSL-KDD KDDTest+** ({metrics['test_rows']:,} rows), trained "
        f"on **KDDTrain+** ({metrics['train_rows']:,} rows):",
        "",
        "| Accuracy | Precision | Recall | F1 | False positive rate | ROC-AUC | PR-AUC |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        "| " + " | ".join(
            f"{result[key]:.2%}" for key in
            ("accuracy", "precision", "recall", "f1", "false_positive_rate", "roc_auc", "pr_auc")
        ) + " |",
        "",
        f"Training cross-validation F1 is {cv_rf['f1']:.2%}, while the official "
        f"test F1 is {result['f1']:.2%}. Official test recall is "
        f"{result['recall']:.2%}; the model misses many anomalies in this split.",
        end,
    ])
    before, remainder = content.split(begin, 1)
    _, after = remainder.split(end, 1)
    path.write_text(before + block + after, encoding="utf-8")


def _sample(frame, limit):
    if limit is None or limit >= len(frame):
        return frame
    if limit < 10:
        raise ValueError("Sample limit must be at least 10 rows")
    selected, _ = train_test_split(
        frame, train_size=limit, stratify=frame["label_binary"], random_state=SEED
    )
    return selected.reset_index(drop=True)


def train(train_path=TRAIN_PATH, test_path=TEST_PATH, output_root=ROOT, train_limit=None,
          test_limit=None, cv_folds=5, rf_trees=100):
    """Train on KDDTrain+, compare three models, evaluate RF on KDDTest+."""
    train_frame = _sample(load_nsl_kdd(train_path), train_limit)
    test_frame = _sample(load_nsl_kdd(test_path), test_limit)
    x_train = train_frame[MODEL_FEATURES]
    y_train = train_frame["label_binary"]
    x_test = test_frame[MODEL_FEATURES]
    y_test = test_frame["label_binary"]
    folds = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=SEED)
    comparisons = []
    for name, estimator in _models(rf_trees).items():
        pipeline = Pipeline([("preprocess", FeaturePreprocessor()), ("model", estimator)])
        scores = cross_validate(
            pipeline, x_train, y_train, cv=folds,
            scoring={"accuracy": "accuracy", "precision": "precision", "recall": "recall",
                     "f1": "f1", "roc_auc": "roc_auc"},
            n_jobs=1, error_score="raise",
        )
        result = {"model": name}
        result.update({metric: float(np.mean(scores[f"test_{metric}"])) for metric in
                       ("accuracy", "precision", "recall", "f1", "roc_auc")})
        comparisons.append(result)
        print(f"CV complete: {name}: F1={result['f1']:.4f}", flush=True)

    final = Pipeline([
        ("preprocess", FeaturePreprocessor()),
        ("model", _models(rf_trees)["Random Forest"]),
    ]).fit(x_train, y_train)
    prediction = final.predict(x_test)
    probability = final.predict_proba(x_test)[:, 1]
    matrix = confusion_matrix(y_test, prediction, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    metrics = {
        "dataset": "NSL-KDD", "train_split": "KDDTrain+.txt",
        "test_split": "KDDTest+.txt", "model": "Random Forest",
        "train_rows": int(len(train_frame)), "test_rows": int(len(test_frame)),
        "cv_folds": cv_folds, "random_seed": SEED,
        "evaluation": {
            "accuracy": float(accuracy_score(y_test, prediction)),
            "precision": float(precision_score(y_test, prediction, zero_division=0)),
            "recall": float(recall_score(y_test, prediction, zero_division=0)),
            "f1": float(f1_score(y_test, prediction, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)),
            "roc_auc": float(roc_auc_score(y_test, probability)),
            "pr_auc": float(average_precision_score(y_test, probability)),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        },
        "cross_validation": comparisons,
    }
    output_root = Path(output_root)
    reports = output_root / "reports"
    figures = reports / "figures"
    artifacts = output_root / "models" / "v1"
    reports.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    _save_figures(y_test, prediction, probability, figures)
    (reports / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    _update_readme(metrics, output_root)
    cv_rows = [
        f"| {row['model']} | " + " | ".join(f"{row[key]:.4f}" for key in
        ("accuracy", "precision", "recall", "f1", "roc_auc")) + " |"
        for row in comparisons
    ]
    evaluated = metrics["evaluation"]
    markdown = "\n".join([
        "# NSL-KDD evaluation", "",
        f"Random Forest trained on {len(train_frame):,} KDDTrain+ rows; evaluated once on "
        f"{len(test_frame):,} KDDTest+ rows. Seed: {SEED}.", "",
        "## Five-fold training cross-validation (mean)", "",
        "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |",
        "|---|---:|---:|---:|---:|---:|", *cv_rows, "",
        "## Official test split: Random Forest", "",
        *[f"- {key.replace('_', ' ').title()}: {value:.4f}" for key, value in
          evaluated.items() if key != "confusion_matrix"],
        f"- Confusion matrix (TN, FP, FN, TP): {tn}, {fp}, {fn}, {tp}", "",
        "The official test split includes attack types absent from training and has a "
        "different distribution. Cross-validation scores should not be substituted for test scores.",
        "",
    ])
    (reports / "metrics.md").write_text(markdown, encoding="utf-8")
    fitted_preprocessor = final.named_steps["preprocess"]
    joblib.dump(final.named_steps["model"], artifacts / "model.joblib")
    joblib.dump(fitted_preprocessor.scaler_, artifacts / "scaler.joblib")
    joblib.dump(fitted_preprocessor.encoders_, artifacts / "label_encoders.joblib")
    (artifacts / "feature_names.json").write_text(
        json.dumps(fitted_preprocessor.feature_names_, indent=2) + "\n", encoding="utf-8"
    )
    metadata = {
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "NSL-KDD", "train_split": "KDDTrain+.txt",
        "test_split": "KDDTest+.txt", "train_rows": len(train_frame),
        "test_rows": len(test_frame), "sklearn_version": sklearn.__version__,
        "random_seed": SEED, "git_commit": _git_commit(), "evaluation": evaluated,
    }
    (artifacts / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-path", type=Path, default=TRAIN_PATH)
    parser.add_argument("--test-path", type=Path, default=TEST_PATH)
    parser.add_argument("--output-root", type=Path, default=ROOT)
    parser.add_argument("--train-limit", type=int)
    parser.add_argument("--test-limit", type=int)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--rf-trees", type=int, default=100)
    args = parser.parse_args()
    result = train(**vars(args))
    print(f"Official test F1: {result['evaluation']['f1']:.4f}")


if __name__ == "__main__":
    main()
