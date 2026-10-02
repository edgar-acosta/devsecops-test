"""
Módulo de restablecimiento de contraseñas.
"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import closing


DB_PATH = "users.db"
TOKEN_EXPIRY_SECONDS = 900

SECRET_KEY = os.environ.get("RESET_TOKEN_SECRET")
if not SECRET_KEY:
    raise RuntimeError("RESET_TOKEN_SECRET environment variable is required")
SECRET_KEY = SECRET_KEY.encode()


def generate_reset_token(user_email: str) -> str:
    """
    Genera un token de restablecimiento de contraseña.
    """
    timestamp = int(time.time())
    random_part = secrets.token_urlsafe(32)
    token = f"{timestamp}.{random_part}"
    return token


def save_reset_token(user_email: str, token: str) -> None:
    """
    Guarda el token de restablecimiento en la base de datos.
    """
    token_hash = hmac.new(SECRET_KEY, token.encode(), hashlib.sha256).hexdigest()

    with closing(sqlite3.connect(DB_PATH, isolation_level=None)) as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM reset_tokens WHERE email = ?", (user_email,))
            conn.execute(
                "INSERT INTO reset_tokens (email, token) VALUES (?, ?)",
                (user_email, token_hash)
            )
            conn.commit()
        except sqlite3.Error:
            if conn.in_transaction:
                conn.rollback()
            raise


def verify_reset_token(user_email: str, token: str) -> bool:
    """
    Verifica un token de restablecimiento.
    """
    try:
        timestamp_str, _ = token.split(".", 1)
        timestamp = int(timestamp_str)
    except (ValueError, AttributeError):
        return False

    if not (0 <= time.time() - timestamp <= TOKEN_EXPIRY_SECONDS):
        return False

    token_hash = hmac.new(SECRET_KEY, token.encode(), hashlib.sha256).hexdigest()

    with closing(sqlite3.connect(DB_PATH, isolation_level=None)) as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT token FROM reset_tokens WHERE email = ?",
                (user_email,)
            ).fetchone()
            if row is None:
                conn.rollback()
                return False
            stored_hash = row[0]
            if not hmac.compare_digest(stored_hash, token_hash):
                conn.rollback()
                return False
            conn.execute("DELETE FROM reset_tokens WHERE email = ?", (user_email,))
            conn.commit()
        except sqlite3.Error:
            if conn.in_transaction:
                conn.rollback()
            raise

    return True