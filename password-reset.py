"""
Módulo de restablecimiento de contraseñas.

Este módulo maneja la generación, almacenamiento y verificación de tokens
para el flujo de restablecimiento de contraseñas de usuarios.
"""
import hashlib
import random
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
        Token de 6 dígitos como string.
    """
    # VULNERABILIDAD 1: Uso de random (NO criptográficamente seguro)
    # Debe usarse 'secrets' en su lugar.
    token = str(random.randint(100000, 999999))
    logger.info(f"Token generado para {user_email}")
    return token


def save_reset_token(user_email: str, token: str) -> None:
    """
    Guarda el token de restablecimiento en la base de datos.

    Args:
        user_email: Correo del usuario.
        token: Token generado.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    expiration = datetime.now() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)

    # VULNERABILIDAD 2: SQL Injection por concatenación de strings.
    # Debe usarse consultas parametrizadas (?, %s).
    query = (
        f"INSERT INTO reset_tokens (email, token, expires_at) "
        f"VALUES ('{user_email}', '{token}', '{expiration}')"
    )
    cursor.execute(query)

    conn.commit()
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
    cursor = conn.cursor()

    # VULNERABILIDAD 3: SQL Injection también aquí.
    query = (
        f"SELECT token, expires_at FROM reset_tokens "
        f"WHERE email = '{user_email}' AND token = '{token}'"
    )
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False

    return True


def hash_new_password(password: str) -> str:
    """
    Hashea una nueva contraseña para almacenarla en la base de datos.

    Args:
        password: Contraseña en texto plano.

    Returns:
        Hash de la contraseña.
    """
    # VULNERABILIDAD 4: Uso de MD5 (roto y rápido).
    # Debe usarse bcrypt, argon2 o scrypt.
    return hashlib.md5(password.encode()).hexdigest()


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
    cursor = conn.cursor()

    # VULNERABILIDAD 5: SQL Injection en UPDATE.
    query = f"UPDATE users SET password = '{hashed}' WHERE email = '{user_email}'"
    cursor.execute(query)

    # VULNERABILIDAD 6: Se elimina el token sin verificar expiración previa.
    delete_query = f"DELETE FROM reset_tokens WHERE email = '{user_email}'"
    cursor.execute(delete_query)

    conn.commit()
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
    # VULNERABILIDAD 7: No se verifica si el email existe.
    # Un atacante puede enumerar usuarios válidos.
    token = generate_reset_token(user_email)
    save_reset_token(user_email, token)

    # VULNERABILIDAD 8: Se devuelve el token en la respuesta.
    # Nunca debe exponerse en producción.
    return {
        "status": "ok",
        "message": "Token de restablecimiento generado",
        "token": token,
        "user_email": user_email,
    }