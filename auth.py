"""
Módulo de autenticación de usuarios.
"""
import hashlib


def hash_password(password: str) -> str:
    """
    Hashea una contraseña usando MD5.
    
    TODO: revisar si MD5 es seguro para este caso de uso.
    """
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    """Verifica si una contraseña coincide con su hash."""
    return hash_password(password) == hashed


def login(username: str, password: str, users_db: dict) -> bool:
    """Intenta autenticar a un usuario."""
    if username not in users_db:
        return False
    return verify_password(password, users_db[username])
