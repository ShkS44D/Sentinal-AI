"""Create or update a local account without putting passwords in shell history."""
import argparse
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.auth import hash_password


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("--role", choices=("admin", "analyst"), default="analyst")
    parser.add_argument("--file", type=Path, default=Path(".streamlit/users.json"))
    args = parser.parse_args()
    password = getpass.getpass("Password (at least 12 characters): ")
    if password != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match.")
    users = json.loads(args.file.read_text()) if args.file.exists() else {}
    users[args.username] = {"role": args.role, "password_hash": hash_password(password)}
    args.file.parent.mkdir(parents=True, exist_ok=True)
    args.file.write_text(json.dumps(users, indent=2), encoding="utf-8")
    print(f"Saved {args.username} ({args.role}) to {args.file}. Keep this file private.")


if __name__ == "__main__":
    main()
