"""
Módulo de restablecimiento de contraseñas.
"""
import hashlib
import secrets
import sqlite3
import time


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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM reset_tokens WHERE email = ?", (user_email,))

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    cursor.execute(
        "INSERT INTO reset_tokens (email, token) VALUES (?, ?)",
        (user_email, token_hash)
    )

    conn.commit()
    conn.close()


def verify_reset_token(user_email: str, token: str) -> bool:
    """
    Verifica un token de restablecimiento.
    """
    try:
        timestamp_str, _ = token.split(".", 1)
        timestamp = int(timestamp_str)
    except (ValueError, AttributeError):
        return False

    if time.time() - timestamp > TOKEN_EXPIRY_SECONDS:
        return False

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT token FROM reset_tokens WHERE email = ? AND token = ?",
        (user_email, token_hash)
    )
    row = cursor.fetchone()
    conn.close()

    return row is not None


def hash_new_password(password: str) -> str:
    """
    Hashea una nueva contraseña.
    """
    salt = secrets.token_bytes(16)
    hash_bytes = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=64
    )
    return f"scrypt${salt.hex()}${hash_bytes.hex()}"