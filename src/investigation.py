"""Plain-language observations from alert feature values."""

import pandas as pd

from src.prediction import preprocess


def sensitivity_evidence(features, reference, assets):
    """Measure probability changes replacing one value by a reference value.

    This is local sensitivity, not causal attribution; correlated features and
    unrealistic single-feature combinations can affect the result.
    """
    rows = [dict(features)]
    for feature in assets.feature_names:
        changed = dict(features)
        changed[feature] = reference[feature]
        rows.append(changed)
    probabilities = assets.model.predict_proba(preprocess(pd.DataFrame(rows), assets, unknown_policy="encode"))[:, 1]
    return pd.DataFrame([
        {"Feature": name, "Observed": str(features[name]), "Reference": str(reference[name]),
         "Probability change": float(probabilities[0] - probabilities[index + 1])}
        for index, name in enumerate(assets.feature_names)
    ]).sort_values("Probability change", ascending=False)


def explain_alert(features):
    """Return descriptive heuristics, not an explanation of model internals."""
    observations = []
    for name, description in (
        ("serror_rate", "a large share of recent host connections had SYN errors"),
        ("srv_serror_rate", "a large share of same-service connections had SYN errors"),
        ("rerror_rate", "a large share of recent host connections were rejected"),
    ):
        value = float(features.get(name, 0) or 0)
        if value >= 0.5:
            observations.append(f"{name} is {value:.2f}: {description}")
    for name, description in (
        ("count", "recent connections to the same destination host"),
        ("srv_count", "recent connections to the same service"),
        ("dst_host_srv_count", "recent connections to this host and service"),
    ):
        value = int(float(features.get(name, 0) or 0))
        if value >= 100:
            observations.append(f"{name} is {value}: many {description}")
    if not observations:
        return (
            "No simple high-rate or high-count pattern stands out in the displayed features. "
            "Review the complete record and surrounding activity."
        )
    return ". ".join(observations[:3]) + "."
