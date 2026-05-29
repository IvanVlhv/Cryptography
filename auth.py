import json
import time
from pathlib import Path
from crypto import hash_password, verify_password

USERS_FILE = Path("users.json")


def _load_users() -> dict:
    if USERS_FILE.exists():
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_users(users: dict) -> None:
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def register_user(username: str, password: str) -> tuple[bool, str]:
    if not username or not password:
        return False, "Username and password are required"
    if len(username) < 3 or len(username) > 32:
        return False, "Username must be 3–32 characters"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not all(c.isalnum() or c == "_" for c in username):
        return False, "Username may only contain letters, digits, and underscores"

    users = _load_users()
    if username in users:
        return False, "Username already taken"

    users[username] = {
        "hash": hash_password(password),
        "registered_at": time.time(),
    }
    _save_users(users)
    return True, "Registration successful"


def authenticate_user(username: str, password: str) -> tuple[bool, str]:
    users = _load_users()

    if username not in users:
        # Dummy verify to prevent timing-based username enumeration
        verify_password("$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
        return False, "Invalid username or password"

    if verify_password(users[username]["hash"], password):
        return True, "Authentication successful"
    return False, "Invalid username or password"


def user_exists(username: str) -> bool:
    return username in _load_users()
