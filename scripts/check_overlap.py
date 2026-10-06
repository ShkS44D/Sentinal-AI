"""Check exact feature-and-label overlap of the legacy sample and KDDTrain+."""

from pathlib import Path

import pandas as pd

from src.data import MODEL_FEATURES, TRAIN_PATH, load_nsl_kdd

ROOT = Path(__file__).resolve().parents[1]


def check_overlap(train_path=TRAIN_PATH, legacy_dir=ROOT / "models" / "legacy"):
    import pickle

    legacy_dir = Path(legacy_dir)
    with (legacy_dir / "label_encoders.pkl").open("rb") as file:
        encoders = pickle.load(file)  # Trusted bundled legacy artifact only.
    with (legacy_dir / "feature_names.pkl").open("rb") as file:
        features = pickle.load(file)  # Trusted bundled legacy artifact only.
    sample = pd.read_csv(legacy_dir / "validation_with_labels.csv")
    train = load_nsl_kdd(train_path)
    if list(features) != MODEL_FEATURES:
        raise ValueError("Legacy feature order differs from the official feature order")
    for column, encoder in encoders.items():
        mapping = {name: index for index, name in enumerate(encoder.classes_)}
        train[column] = train[column].map(mapping)
    train = train.dropna(subset=list(encoders))
    keys = list(features) + ["class"]
    train = train[features].assign(**{"class": train["label_binary"]})
    left = pd.DataFrame(sample[keys].to_numpy(dtype=float).round(8), columns=keys)
    right = pd.DataFrame(train[keys].to_numpy(dtype=float).round(8), columns=keys)
    found = left.merge(right.drop_duplicates(), on=keys, how="left", indicator=True)
    overlap = int((found["_merge"] == "both").sum())
    return len(sample), overlap


if __name__ == "__main__":
    total, overlap = check_overlap()
    print(f"Legacy validation sample: {overlap}/{total} rows exactly match KDDTrain+ features and binary label")
