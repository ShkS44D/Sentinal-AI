"""Measured error analysis on the official held-out split."""
import hashlib
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import brier_score_loss, confusion_matrix

from src.data import TEST_PATH, load_nsl_kdd
from src.model import MODEL_DIR, load_assets
from src.prediction import preprocess

ROOT = Path(__file__).resolve().parents[1]


def threshold_metrics(labels, probabilities, threshold):
    tn, fp, fn, tp = confusion_matrix(labels, np.asarray(probabilities) >= threshold, labels=[0, 1]).ravel()
    return {
        "threshold": threshold, "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
        "recall": float(tp / (tp + fn)) if tp + fn else 0.0,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
    }


def error_analysis(frame, probabilities):
    labels = frame["label_binary"].to_numpy()
    probabilities = np.asarray(probabilities)
    predictions = probabilities >= 0.5
    families = []
    for family, rows in frame.groupby("attack_family"):
        mask = frame["attack_family"].eq(family).to_numpy()
        correct = int((predictions[mask] == labels[mask]).sum())
        families.append({"family": family, "rows": len(rows), "correct": correct,
                         "missed_or_false_alarms": len(rows) - correct,
                         "binary_detection_rate": correct / len(rows)})
    calibration = []
    for index in range(10):
        lower = index / 10
        upper = (index + 1) / 10
        mask = (probabilities >= lower) & ((probabilities < upper) if upper < 1 else (probabilities <= upper))
        if mask.any():
            calibration.append({"band": f"{lower:.1f}–{upper:.1f}", "rows": int(mask.sum()),
                                "mean_probability": float(probabilities[mask].mean()),
                                "observed_anomaly_rate": float(labels[mask].mean())})
    return {"dataset": "NSL-KDD", "split": "KDDTest+", "rows": len(frame),
            "decision_rule": "probability >= threshold; exact ties are anomalies",
            "thresholds": [threshold_metrics(labels, probabilities, t) for t in (0.2, 0.3, 0.5, 0.7, 0.9)],
            "families": families, "calibration": calibration,
            "brier_score": float(brier_score_loss(labels, probabilities))}


def main():
    assets = load_assets()
    frame = load_nsl_kdd(TEST_PATH)
    probabilities = assets.model.predict_proba(preprocess(frame, assets, unknown_policy="encode"))[:, 1]
    report = error_analysis(frame, probabilities)
    report["model_sha256"] = hashlib.sha256((MODEL_DIR / "model.joblib").read_bytes()).hexdigest()
    report["test_sha256"] = hashlib.sha256(TEST_PATH.read_bytes()).hexdigest()
    target = ROOT / "reports" / "reliability.json"
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Saved {target}")


if __name__ == "__main__":
    main()
