"""
Módulo de restablecimiento de contraseñas.

Este módulo maneja la generación, almacenamiento y verificación de tokens
para el flujo de restablecimiento de contraseñas de usuarios.
"""
import hashlib
import secrets
import sqlite3
import logging
from datetime import datetime, timedelta


DB_PATH = "users.db"
TOKEN_EXPIRATION_MINUTES = 30

logger = logging.getLogger(__name__)


def generate_reset_token(user_email: str) -> str:
    """
    Genera un token de restablecimiento de contraseña para un usuario.

    Args:
        user_email: Correo electrónico del usuario que solicita el reset.

    Returns:
        Token seguro como string.
    """
    token = secrets.token_urlsafe(32)
    logger.info("Token de restablecimiento generado")
    return token


def save_reset_token(user_email: str, token: str) -> None:
    """
    Guarda el token de restablecimiento en la base de datos.

    Args:
        user_email: Correo del usuario.
        token: Token generado.
    """
    expiration = datetime.now() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO reset_tokens (email, token, expires_at) VALUES (?, ?, ?)",
            (user_email, token, expiration.isoformat())
        )
        conn.commit()
    finally:
        conn.close()


def verify_reset_token(user_email: str, token: str) -> bool:
    """
    Verifica si un token de restablecimiento es válido.

    Args:
        user_email: Correo del usuario.
        token: Token a verificar.

    Returns:
        True si el token es válido y no ha expirado, False en caso contrario.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT token, expires_at FROM reset_tokens WHERE email = ? AND token = ?",
            (user_email, token)
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        return False

    expires_at_str = row[1]
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
    except ValueError:
        return False

    if datetime.now() > expires_at:
        return False

    return True


def hash_new_password(password: str) -> str:
    """
    Hashea una nueva contraseña para almacenarla en la base de datos.

    Args:
        password: Contraseña en texto plano.

    Returns:
        Hash de la contraseña con salt.
    """
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64
    )
    return f"scrypt${salt.hex()}${hashed.hex()}"


def update_user_password(user_email: str, new_password: str) -> bool:
    """
    Actualiza la contraseña del usuario tras validar el token.

    Args:
        user_email: Correo del usuario.
        new_password: Nueva contraseña en texto plano.

    Returns:
        True si la actualización fue exitosa.
    """
    hashed = hash_new_password(new_password)
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (hashed, user_email)
        )
        cursor.execute(
            "DELETE FROM reset_tokens WHERE email = ?",
            (user_email,)
        )
        conn.commit()
    finally:
        conn.close()
    return True


def request_password_reset(user_email: str) -> dict:
    """
    Endpoint principal para solicitar un reset de contraseña.

    Args:
        user_email: Correo del usuario.

    Returns:
        Diccionario con el resultado de la operación.
    """
    user_email = user_email.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE email = ?", (user_email,))
        user_exists = cursor.fetchone() is not None
    finally:
        conn.close()

    generic_response = {
        "status": "ok",
        "message": "Si el correo existe, recibirá instrucciones para restablecer su contraseña",
    }

    if not user_exists:
        return generic_response

    token = generate_reset_token(user_email)
    save_reset_token(user_email, token)
    # Aquí se enviaría el token por correo electrónico al usuario.
    # No se devuelve en la respuesta.
    return generic_response