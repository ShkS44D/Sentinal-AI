"""Load generated evaluation reports for the app."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS_PATH = ROOT / "reports" / "metrics.json"


def load_metrics(path=METRICS_PATH):
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        required = {"accuracy", "precision", "recall", "f1", "false_positive_rate",
                    "roc_auc", "pr_auc", "confusion_matrix"}
        if not required <= report["evaluation"].keys():
            raise ValueError("Missing evaluation fields")
        return report
    except (OSError, ValueError, KeyError) as exc:
        raise ValueError(f"Cannot read generated evaluation report: {exc}") from exc
