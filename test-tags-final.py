import hashlib
import os
import sqlite3
from contextlib import closing

DB_PATH = os.environ.get("USERS_DB", "users.db")

def get_user(user_id):
    user_id = int(user_id)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def hash_password(password):
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + key.hex()