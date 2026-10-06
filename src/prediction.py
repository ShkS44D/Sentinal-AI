"""Prepare and classify network connection features."""
import pandas as pd
from src.model import Assets

class PreprocessingError(ValueError):
    """Input cannot be transformed for the saved model."""

def preprocess(raw: dict | pd.DataFrame, assets: Assets, *, unknown_policy="error"):
    """Encode category names, order features, and scale one or more rows."""
    frame = pd.DataFrame([raw]) if isinstance(raw, dict) else raw.copy()
    missing = [name for name in assets.feature_names if name not in frame]
    if missing:
        raise PreprocessingError(f"Missing required features: {', '.join(missing)}")
    frame = frame[assets.feature_names].copy()
    for column, encoder in assets.encoders.items():
        frame[column] = frame[column].astype(object)
        values = frame[column]
        text = values.map(lambda value: isinstance(value, str))
        unknown = sorted(set(values[text]) - set(encoder.classes_))
        if unknown and unknown_policy == "error":
            raise PreprocessingError(
                f"Unknown {column}: {', '.join(map(str, unknown))}. Choose a category used during training."
            )
        if unknown_policy == "encode":
            mapping = {name: index for index, name in enumerate(encoder.classes_)}
            frame.loc[text, column] = values[text].map(mapping).fillna(-1).astype(int)
        else:
            frame.loc[text, column] = encoder.transform(values[text])
    try:
        frame = frame.apply(pd.to_numeric, errors="raise")
        if frame.isna().any().any():
            raise PreprocessingError("Input contains missing values.")
        return assets.scaler.transform(frame)
    except (ValueError, TypeError) as exc:
        raise PreprocessingError(f"Invalid feature value: {exc}") from exc

def predict(raw: dict | pd.DataFrame, assets: Assets, *, unknown_policy="error") -> tuple[int, float]:
    prepared = preprocess(raw, assets, unknown_policy=unknown_policy)
    label = int(assets.model.predict(prepared)[0])
    confidence = float(assets.model.predict_proba(prepared)[0].max())
    return label, confidence

def readable_sample(row: pd.Series, assets: Assets) -> pd.Series:
    """Decode category columns in a display copy of an encoded CSV row."""
    result = row.astype(object).copy()
    for column, encoder in assets.encoders.items():
        result[column] = encoder.inverse_transform([int(row[column])])[0]
    return result
