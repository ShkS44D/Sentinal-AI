"""Download the full NSL-KDD official split from a public mirror."""

import argparse
import hashlib
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master"
SHA256 = {
    "KDDTrain+.txt": "1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95",
    "KDDTest+.txt": "fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84",
}


def download(destination: Path = ROOT / "data") -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name, expected in SHA256.items():
        path = destination / name
        if path.exists():
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual == expected:
                print(f"Verified existing {name}: {actual}")
                continue
            raise ValueError(f"Existing {path} has unexpected SHA-256 {actual}; refusing to overwrite")
        with urlopen(f"{BASE}/{name}", timeout=120) as response:
            content = response.read()
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise ValueError(f"Downloaded {name} has unexpected SHA-256 {actual}")
        path.write_bytes(content)
        print(f"Downloaded {name}: {actual}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=ROOT / "data")
    download(parser.parse_args().destination)
