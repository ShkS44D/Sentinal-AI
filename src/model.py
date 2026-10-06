"""Load bundled, trusted versioned model artifacts."""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import json

import joblib

MODEL_DIR = Path(__file__).resolve().parents[1] / "models" / "v1"

class ModelLoadError(RuntimeError):
    """A required model artifact is missing or incompatible."""

@dataclass(frozen=True)
class Assets:
    model: object
    scaler: object
    encoders: dict
    feature_names: list[str]

@lru_cache(maxsize=1)
def load_assets() -> Assets:
    """Load only the trusted artifacts bundled with this project."""
    loaded = []
    for name in ("model", "scaler", "label_encoders"):
        path = MODEL_DIR / f"{name}.joblib"
        try:
            loaded.append(joblib.load(path))
        except (OSError, ValueError, ImportError, AttributeError) as exc:
            raise ModelLoadError(f"Cannot load {path.name}: {exc}") from exc
    path = MODEL_DIR / "feature_names.json"
    try:
        feature_names = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelLoadError(f"Cannot load {path.name}: {exc}") from exc
    model, scaler, encoders = loaded
    if not isinstance(encoders, dict) or len(feature_names) != scaler.n_features_in_:
        raise ModelLoadError("Model artifacts have incompatible feature definitions.")
    return Assets(model, scaler, encoders, list(feature_names))
