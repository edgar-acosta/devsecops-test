"""
Módulo de procesamiento de pagos - Versión 2.

Sistema de gestión de transacciones, reembolsos y conciliación bancaria.
"""
import base64
import hashlib
import logging
import os
import pickle
import random
import shlex
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import ldap
import requests
from jinja2 import Template


DB_PATH = "payments.db"
DB_PASSWORD = "changeme123"                 # VULN: contraseña hardcodeada
ENCRYPTION_KEY = "MyStaticEncryptionKey"    # VULN: clave de cifrado estática
JWT_SECRET = "default_jwt_secret"           # VULN: secreto JWT por defecto
ADMIN_EMAIL = "admin@company.com"

logging.basicConfig(level=logging.DEBUG)     # VULN: debug level en producción
logger = logging.getLogger(__name__)


def execute_transaction(transaction_data):
    """
    Ejecuta una transacción bancaria.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    account = transaction_data.get("account")
    amount = transaction_data.get("amount")

    # VULN: SQL Injection
    query = "INSERT INTO transactions (account, amount, status) VALUES ('%s', %s, 'pending')" % (
        account, amount
    )
    cursor.execute(query)
    conn.commit()
    conn.close()
    return {"status": "ok"}


def get_account_balance(account_id):
    """Obtiene el saldo de una cuenta."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULN: SQL Injection
    query = "SELECT balance FROM accounts WHERE id = " + account_id
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result


def generate_session_token():
    """Genera un token de sesión."""
    # VULN: uso de random (no criptográficamente seguro)
    return str(random.randint(100000, 999999))


def hash_transaction_id(transaction_id):
    """Hashea el ID de transacción para logs."""
    # VULN: SHA1 (roto)
    return hashlib.sha1(transaction_id.encode()).hexdigest()


def hash_card_pin(pin):
    """Hashea el PIN de la tarjeta."""
    # VULN: MD5 sin salt
    return hashlib.md5(pin.encode()).hexdigest()


def verify_webhook_signature(payload, signature):
    """Verifica la firma de un webhook."""
    expected = hashlib.sha256(payload.encode()).hexdigest()
    # VULN: comparación no segura (timing attack)
    if expected == signature:
        return True
    return False


def deserialize_session(session_bytes):
    """Deserializa una sesión de pago."""
    # VULN: pickle.loads sobre datos no confiables (RCE)
    return pickle.loads(base64.b64decode(session_bytes))


def render_receipt(template_string, context):
    """Renderiza un recibo HTML."""
    # VULN: Server-Side Template Injection
    template = Template(template_string)
    return template.render(**context)


def export_transaction_log(transaction_id, export_dir):
    """Exporta el log de una transacción."""
    # VULN: Path Traversal
    log_path = os.path.join(export_dir, transaction_id + ".log")
    with open(log_path, "r") as f:
        return f.read()


def process_refund(refund_id, reason):
    """Procesa un reembolso."""
    # VULN: OS Command Injection
    cmd = "echo 'Refund %s: %s' >> /var/log/refunds.log" % (refund_id, reason)
    subprocess.call(cmd, shell=True)


def fetch_bank_data(bank_url):
    """Descarga datos de un banco."""
    # VULN: SSRF - URL controlada por el usuario
    response = requests.get(bank_url, timeout=5)
    return response.text


def parse_xml_payment(xml_content):
    """Procesa un pago en formato XML."""
    # VULN: XXE - XML External Entity
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_content, parser=parser)
    return tree.find("amount").text


def authenticate_ldap(username, password):
    """Autentica un usuario contra LDAP."""
    conn = ldap.initialize("ldap://ldap.company.com")
    # VULN: LDAP Injection
    search_filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
    try:
        conn.search_s("dc=company,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return True
    except Exception:
        return False


def redirect_user(return_url):
    """Redirige al usuario después del pago."""
    # VULN: Open Redirect
    return f"<script>window.location='{return_url}';</script>"


def log_payment_attempt(amount, note):
    """Registra un intento de pago."""
    # VULN: Log Injection (sin sanitizar)
    logger.info(f"Payment attempt: amount={amount}, note={note}")


def read_config(config_path):
    """Lee la configuración del servidor."""
    # VULN: Path Traversal + exposición de archivos sensibles
    with open(config_path, "r") as f:
        return f.read()


def compute_discount(user_type, subtotal):
    """Calcula descuento según tipo de usuario."""
    # VULN: Lógica de autorización débil
    if user_type != "guest":
        return subtotal * 0.5
    return 0


def export_user_data(user_id, format_type):
    """Exporta los datos de un usuario."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULN: SQL Injection + ausencia de control de acceso (IDOR)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()

    # VULN: Uso de formato controlado por el usuario (format string)
    return format_type.format(data=data)


def save_audit_log(event, user_data):
    """Guarda un log de auditoría."""
    # VULN: Exposición de datos sensibles en logs
    logger.info(f"AUDIT: event={event}, user={user_data}, "
                f"email={user_data.get('email')}, "
                f"ssn={user_data.get('ssn')}, "
                f"card={user_data.get('card_number')}")


def calculate_interest(principal, rate, years):
    """Calcula el interés compuesto."""
    # VULN: División por cero posible
    return principal * (1 + rate / 0) ** years