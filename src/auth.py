"""Teacher credentials and short-lived, in-memory login sessions."""

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from threading import Lock

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field


CREDENTIALS_FILE = Path(__file__).with_name("teachers.json")
SESSION_SECONDS = 8 * 60 * 60
PASSWORD_ITERATIONS = 600_000
sessions: dict[str, tuple[str, float]] = {}
session_lock = Lock()
bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), PASSWORD_ITERATIONS
    ).hex()


def login(credentials: LoginRequest) -> dict[str, str]:
    try:
        teachers = json.loads(CREDENTIALS_FILE.read_text())
    except FileNotFoundError:
        raise HTTPException(
            status_code=503, detail="Teacher login is not configured. Contact the school administrator."
        ) from None

    record = teachers.get(credentials.username)
    # Perform the same password hashing work for unknown usernames.
    salt = record["salt"] if record else "00" * 16
    expected = record["password_hash"] if record else "00" * 32
    valid_password = hmac.compare_digest(
        hash_password(credentials.password, salt), expected
    )
    if not record or not valid_password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with session_lock:
        expired = [key for key, (_, expiry) in sessions.items() if expiry <= now]
        for key in expired:
            del sessions[key]
        sessions[token] = (credentials.username, now + SESSION_SECONDS)
    return {"access_token": token, "token_type": "bearer", "username": credentials.username}


def require_teacher(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> str:
    token = credentials.credentials if credentials else ""
    with session_lock:
        session = sessions.get(token)
        if session and session[1] > time.monotonic():
            return session[0]
        sessions.pop(token, None)
    raise HTTPException(
        status_code=401,
        detail="Teacher login required or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )


def logout(credentials: HTTPAuthorizationCredentials) -> None:
    with session_lock:
        sessions.pop(credentials.credentials, None)


def main() -> None:
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="Assign or reset a teacher password.")
    parser.add_argument("username")
    args = parser.parse_args()
    if not args.username or len(args.username) > 100:
        parser.error("Username must contain 1 to 100 characters.")
    password = getpass.getpass("New password (at least 12 characters): ")
    if not 12 <= len(password) <= 1024:
        parser.error("Password must contain 12 to 1024 characters.")
    if password != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match.")

    teachers = json.loads(CREDENTIALS_FILE.read_text()) if CREDENTIALS_FILE.exists() else {}
    salt = secrets.token_hex(16)
    teachers[args.username] = {
        "salt": salt,
        "password_hash": hash_password(password, salt),
    }
    descriptor = os.open(CREDENTIALS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as credentials_file:
        json.dump(teachers, credentials_file, indent=2)
        credentials_file.write("\n")
    print(f"Password assigned for {args.username}.")


if __name__ == "__main__":
    main()
