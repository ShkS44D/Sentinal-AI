"""Create a small labeled CSV of real rows from the official NSL-KDD test split."""

from pathlib import Path

from src.data import MODEL_FEATURES, TEST_PATH, load_nsl_kdd

ROOT = Path(__file__).resolve().parents[1]


def create_sample(destination=ROOT / "data" / "sample_traffic.csv"):
    test = load_nsl_kdd(TEST_PATH)
    selected = test.groupby("label_binary", group_keys=False).head(10)
    columns = MODEL_FEATURES + ["label_binary"]
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    selected[columns].to_csv(destination, index=False)
    print(f"Wrote {len(selected)} real KDDTest+ rows to {destination}")


if __name__ == "__main__":
    create_sample()
