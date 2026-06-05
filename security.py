"""Security helpers for the demo banking web app.

This module provides utilities for generating and loading a Fernet key,
encrypting/decrypting login tickets, creating time-limited login tickets,
and hashing/verifying passwords. Run with `--explain` to print a short
description of available functions.

Command to explain code line by line:
python security.py --explain-lines
"""

import argparse  # parse CLI flags like --explain / --explain-lines
import base64  # url-safe base64 encoding for Flask SECRET_KEY derivation
import hashlib  # compute SHA-256 digest of the Fernet key
import json  # serialize/deserialize ticket payloads
import os  # filesystem helpers (exists, open files)
from datetime import datetime, timedelta  # timestamps and expiry calculation

from cryptography.fernet import Fernet, InvalidToken  # symmetric encryption and error
from werkzeug.security import check_password_hash, generate_password_hash  # password hashing utilities


DATA_DIR = os.environ.get("DATA_DIR", ".")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")  # filename where the Fernet key is stored
TOKEN_LIFETIME_MINUTES = 30  # login ticket validity in minutes


def generate_key_if_not_exists():
    """Create one shared Fernet key for both RPC servers if it is missing."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(KEY_FILE):  # only generate once
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(Fernet.generate_key())  # write raw Fernet key bytes


def _load_fernet():
    generate_key_if_not_exists()
    with open(KEY_FILE, "rb") as key_file:  # read the key file
        return Fernet(key_file.read())  # return a Fernet instance for encrypt/decrypt


def encrypt_ticket(data):
    """Encrypt ticket data so the browser and Flask app cannot read it."""
    fernet = _load_fernet()
    payload = json.dumps(data).encode("utf-8")  # JSON -> bytes
    return fernet.encrypt(payload).decode("utf-8")  # returns URL-safe token string


def decrypt_ticket(token):
    """Return ticket data if the token is valid and not expired."""
    try:
        fernet = _load_fernet()
        decrypted = fernet.decrypt(token.encode("utf-8"))  # may raise InvalidToken
        data = json.loads(decrypted.decode("utf-8"))  # parse JSON payload

        expiry_time = datetime.fromisoformat(data["expiry_time"])  # ISO timestamp
        if datetime.utcnow() > expiry_time:  # check expiry
            return None  # expired

        return data  # valid ticket
    except (InvalidToken, KeyError, ValueError, TypeError, json.JSONDecodeError):
        return None  # invalid token or malformed payload


def create_login_ticket(username):
    now = datetime.utcnow()  # issue time in UTC
    return encrypt_ticket(
        {
            "username": username,  # identity stored in ticket
            "issue_time": now.isoformat(),  # when issued
            "expiry_time": (now + timedelta(minutes=TOKEN_LIFETIME_MINUTES)).isoformat(),  # expiry
        }
    )


def hash_password(password):
    return generate_password_hash(password)  # PBKDF2/SHA-based hash from Werkzeug


def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)  # safe compare


def stable_flask_secret():
    """Build a stable development secret from the Fernet key."""
    generate_key_if_not_exists()
    with open(KEY_FILE, "rb") as key_file:
        digest = hashlib.sha256(key_file.read()).digest()  # sha256 of raw key
    return base64.urlsafe_b64encode(digest).decode("utf-8")  # base64 Flask SECRET_KEY


def _explain_text():
    return (
        "security.py: utilities for ticket encryption and password hashing.\n\n"
        "KEY_FILE: path to the Fernet key file. TOKEN_LIFETIME_MINUTES: default token lifetime.\n\n"
        "generate_key_if_not_exists(): create a Fernet key file if missing.\n"
        "_load_fernet(): load a Fernet instance from the key file.\n"
        "encrypt_ticket(data): JSON-serialize and encrypt 'data' for client cookies.\n"
        "decrypt_ticket(token): decrypt token and verify expiry; returns data or None.\n"
        "create_login_ticket(username): convenience helper to create an expiring ticket.\n"
        "hash_password(password): return a Werkzeug password hash.\n"
        "verify_password(password, password_hash): check a plaintext password.\n"
        "stable_flask_secret(): derive a stable Flask SECRET_KEY from the Fernet key.\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="security.py utility")
    parser.add_argument("--explain", action="store_true", help="Print short explanations")
    parser.add_argument(
        "--explain-lines",
        action="store_true",
        help="Print the source file with line numbers (line-by-line view)",
    )
    args = parser.parse_args()
    if args.explain:
        print(_explain_text())
    if args.explain_lines:
        # Print this source file with line numbers so the user can see it line-by-line
        try:
            with open(__file__, "r", encoding="utf-8") as f:
                for i, line in enumerate(f.readlines()):
                    # Show line number and content (rstrip to avoid doubling newlines)
                    print(f"{i+1:3d}: {line.rstrip()}")
        except Exception as e:
            print(f"Could not read source file for explanation: {e}")
