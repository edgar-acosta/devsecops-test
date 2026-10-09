import hashlib
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def run_command(cmd):
    import subprocess
    return subprocess.check_output(f"echo {cmd}", shell=True)