import hashlib
import os
import sqlite3

def vulnerable_query(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (int(user_id),))
    return cursor.fetchone()

def hash_password(password):
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt.hex() + "$" + key.hex()