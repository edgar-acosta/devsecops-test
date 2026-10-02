"""
Módulo de restablecimiento de contraseñas.
"""
import hashlib
import secrets
import sqlite3
import time
from contextlib import closing


DB_PATH = "users.db"
TOKEN_EXPIRY_SECONDS = 900


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
    token_hash = hashlib.sha256(token.encode()).hexdigest()

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

    if time.time() - timestamp