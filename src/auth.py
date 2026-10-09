"""Local password verification and role policy; no plaintext stored passwords."""
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

ROLES = {"admin", "analyst"}


def hash_password(password):
    if len(password) < 12:
        raise ValueError("Use a password of at least 12 characters.")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2_sha256$600000${salt}${digest.hex()}"


def verify_password(password, stored):
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != "pbkdf2_sha256" or int(iterations) != 600_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError, AttributeError):
        return False


def load_users():
    path = os.environ.get("SENTINEL_USERS_FILE")
    if not path:
        return None
    users = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(users, dict) or not users:
        raise ValueError("The users file must contain at least one account.")
    for username, account in users.items():
        if not username or not isinstance(account, dict) or account.get("role") not in ROLES:
            raise ValueError("Each account needs a username, password_hash and admin/analyst role.")
        if not isinstance(account.get("password_hash"), str):
            raise ValueError("Each account needs a password_hash.")
    return users


def permitted(role, page):
    return role in ROLES and (page != "Settings" or role == "admin")
