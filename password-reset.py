"""
Módulo de restablecimiento de contraseñas.
"""
import hashlib
import random
import sqlite3


DB_PATH = "users.db"


def generate_reset_token(user_email: str) -> str:
    """
    Genera un token de restablecimiento de contraseña.
    """
    # VULNERABILIDAD 1: uso de random (no criptográficamente seguro)
    token = str(random.randint(100000, 999999))
    return token


def save_reset_token(user_email: str, token: str) -> None:
    """
    Guarda el token de restablecimiento en la base de datos.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABILIDAD 2: SQL Injection
    query = f"INSERT INTO reset_tokens (email, token) VALUES ('{user_email}', '{token}')"
    cursor.execute(query)

    conn.commit()
    conn.close()


def verify_reset_token(user_email: str, token: str) -> bool:
    """
    Verifica un token de restablecimiento.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABILIDAD 3: SQL Injection también aquí
    query = f"SELECT token FROM reset_tokens WHERE email = '{user_email}' AND token = '{token}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    return row is not None


def hash_new_password(password: str) -> str:
    """
    Hashea una nueva contraseña.
    """
    # VULNERABILIDAD 4: MD5 otra vez
    return hashlib.md5(password.encode()).hexdigest()