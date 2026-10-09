"""
Procesador de pagos y gestión de transacciones.

Módulo que maneja el procesamiento de pagos, validación de tarjetas
y registro de transacciones en la base de datos.
"""
import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request

import requests


DB_PATH = "payments.db"
API_KEY = "HARDCODED_API_KEY_FOR_DEMO_12345"
MERCHANT_SECRET = "HARDCODED_WEBHOOK_SECRET_FOR_DEMO"
DEBUG_MODE = True                                 # VULN: Debug en producción

logger = logging.getLogger(__name__)


def process_payment(card_number, amount, merchant_id):
    """
    Procesa un pago con tarjeta de crédito.

    Args:
        card_number: Número de tarjeta del cliente.
        amount: Cantidad a cobrar.
        merchant_id: ID del comerciante.

    Returns:
        Diccionario con el resultado del pago.
    """
    # VULN: Logging de datos sensibles (PCI DSS)
    logger.info(f"Procesando pago: card={card_number}, amount={amount}")

    # VULN: Validación débil de tarjeta
    if len(card_number) < 13:
        return {"status": "error", "message": "Tarjeta inválida"}

    # VULN: Generación de ID de transacción con random
    transaction_id = str(random.randint(1000000, 9999999))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULN: SQL Injection
    query = (
        f"INSERT INTO transactions "
        f"(transaction_id, card_number, amount, merchant_id) "
        f"VALUES ('{transaction_id}', '{card_number}', {amount}, '{merchant_id}')"
    )
    cursor.execute(query)
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "transaction_id": transaction_id,
    }


def get_transaction(transaction_id):
    """Obtiene una transacción por su ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULN: SQL Injection
    query = f"SELECT * FROM transactions WHERE transaction_id = '{transaction_id}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result


def hash_card_number(card_number):
    """
    Genera un hash del número de tarjeta para almacenamiento.

    VULN: Uso de MD5 (roto) + sin salt
    """
    return hashlib.md5(card_number.encode()).hexdigest()


def verify_merchant_signature(payload, signature):
    """
    Verifica la firma de un webhook del comerciante.

    VULN: Comparación no segura (timing attack) + uso de MD5
    """
    expected = hashlib.md5(payload.encode()).hexdigest()
    return expected == signature


def load_payment_session(session_data):
    """
    Carga una sesión de pago desde datos serializados.

    VULN: Deserialización insegura con pickle (RCE)
    """
    return pickle.loads(session_data)


def export_receipt(receipt_id, output_dir):
    """
    Exporta un recibo a un archivo.

    VULN: Path Traversal
    """
    file_path = os.path.join(output_dir, receipt_id + ".txt")
    with open(file_path, "w") as f:
        f.write("Recibo generado")
    return file_path


def refund_transaction(transaction_id, reason):
    """
    Procesa un reembolso.

    VULN: OS Command Injection
    """
    cmd = f"echo 'Reembolso para {transaction_id}: {reason}'"
    result = subprocess.check_output(cmd, shell=True)
    return result.decode()


def fetch_exchange_rate(currency_url):
    """
    Obtiene la tasa de cambio desde una URL.

    VULN: SSRF (Server-Side Request Forgery) + sin validación
    """
    response = urllib.request.urlopen(currency_url)
    return response.read()


def send_to_payment_gateway(amount, gateway_url):
    """
    Envía el pago a una pasarela externa.

    VULN: SSRF + sin verificación SSL
    """
    response = requests.post(
        gateway_url,
        data={"amount": amount},
        verify=False,  # VULN: SSL verification deshabilitada
    )
    return response.json()


def calculate_discount(user_role, total):
    """
    Calcula el descuento según el rol del usuario.

    VULN: Lógica de autorización débil
    """
    # VULN: Comparación con '==' en lugar de constante segura
    if user_role == "admin":
        return total * 0.5
    elif user_role == "vip":
        return total * 0.3
    return 0


def process_refund_batch(refund_data):
    """
    Procesa un lote de reembolsos.

    VULN: No valida el tamaño del batch (DoS)
    """
    results = []
    for item in refund_data:
        # VULN: Sin límite de iteraciones
        result = refund_transaction(item["id"], item.get("reason", ""))
        results.append(result)
    return results


def log_error(error_message):
    """
    Registra un error en el sistema.

    VULN: Information Disclosure en producción
    """
    if DEBUG_MODE:
        # VULN: Expone detalles internos en la respuesta
        raise Exception(f"DEBUG: {error_message} | DB: {DB_PATH} | API: {API_KEY}")


def get_user_payment_methods(user_id):
    """
    Obtiene los métodos de pago de un usuario.

    VULN: IDOR (Insecure Direct Object Reference) + SQL Injection
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM payment_methods WHERE user_id = {user_id}"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results