import hashlib
import os
import sqlite3

DB_PATH = os.environ.get("USERS_DB_PATH", "users.db")

def get_user(user_id):
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return None
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def hash_password(password):
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt.hex() + "$" + key.hex()