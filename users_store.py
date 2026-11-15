"""
users_store.py
---------------
Simple JSON-backed user store for the 3 family administrator accounts.
In a production system this would be a proper database (Postgres/MySQL)
with a users table, but for this project a JSON file keeps things
transparent and easy to inspect/demo.

Each user record:
    {
      "username": "appa_admin",
      "password_hash": "<werkzeug hash>",
      "full_name": "Appa (Dad)",
      "email": "appa@example.com",
      "role": "Family Administrator"
    }

On first run, 3 default accounts are seeded with the password "Family@123"
(you should change these before any real use — see change_password()).
"""

import os
import json
from werkzeug.security import generate_password_hash, check_password_hash

USERS_PATH = "data/users.json"

DEFAULT_USERS = [
    {
        "username": "appa_admin",
        "full_name": "Appa (Dad)",
        "email": "appa@example.com",
        "role": "Family Administrator",
    },
    {
        "username": "amma_admin",
        "full_name": "Amma (Mom)",
        "email": "amma@example.com",
        "role": "Family Administrator",
    },
    {
        "username": "anna_admin",
        "full_name": "Anna (Elder Sibling)",
        "email": "anna@example.com",
        "role": "Family Administrator",
    },
]

DEFAULT_PASSWORD = "Family@123"


def _seed_if_missing(force: bool = False):
    # To keep demo behavior consistent, allow forcing reset of
    # the code-defined admin users.
    if os.path.exists(USERS_PATH) and not force:
        return

    os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
    users = []
    for u in DEFAULT_USERS:
        rec = dict(u)
        rec["password_hash"] = generate_password_hash(DEFAULT_PASSWORD)
        users.append(rec)
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=2)


def _load():
    _seed_if_missing(force=False)
    with open(USERS_PATH) as f:
        return json.load(f)




def _save(users):
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=2)


def get_all_users():
    return _load()


def get_user(username):
    for u in _load():
        if u["username"] == username:
            return u
    return None


def verify_login(username, password):
    user = get_user(username)
    if not user:
        return None
    if check_password_hash(user["password_hash"], password):
        return user
    return None


def change_password(username, new_password):
    users = _load()
    for u in users:
        if u["username"] == username:
            u["password_hash"] = generate_password_hash(new_password)
            _save(users)
            return True
    return False


def update_email(username, new_email):
    users = _load()
    for u in users:
        if u["username"] == username:
            u["email"] = new_email
            _save(users)
            return True
    return False


def update_full_name(username, new_full_name):
    users = _load()
    for u in users:
        if u["username"] == username:
            u["full_name"] = new_full_name
            _save(users)
            return True
    return False


def rename_user(old_username, new_username, new_full_name=None):
    """Rename a user (login username) and optionally update full_name.

    Returns:
      (ok: bool, error: str|None)
    """
    old_username = (old_username or "").strip()
    new_username = (new_username or "").strip()

    if not old_username or not new_username:
        return False, "Username cannot be empty."
    if old_username == new_username:
        # Still allow updating full name.
        if new_full_name is None:
            return True, None

    users = _load()

    # Ensure new username is not taken.
    for u in users:
        if u["username"] == new_username and u["username"] != old_username:
            return False, "That username is already taken."

    found = False
    for u in users:
        if u["username"] == old_username:
            found = True
            u["username"] = new_username
            if new_full_name is not None:
                u["full_name"] = new_full_name
            break

    if not found:
        return False, "User not found."

    _save(users)
    return True, None

