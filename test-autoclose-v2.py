import hashlib
import os
import sqlite3
from contextlib import closing

def get_user(user_id):
    db_path = os.environ.get("USERS_DB", "users.db")
    with closing(sqlite3.connect(db_path)) as conn:
        query = "SELECT * FROM users WHERE id = ?"
        return conn.execute(query, (int(user_id),)).fetchone()

def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + "$" + hashed.hex()

def run_command(cmd):
    import subprocess
    return subprocess.check_output(["echo", str(cmd)])