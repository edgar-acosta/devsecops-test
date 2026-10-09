"""
Módulo de conciliación bancaria - Versión 3.

Sistema de conciliación de transacciones y gestión de disputas.
"""
import hashlib
import hmac
import json
import os
import pickle
import random
import re
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, request, jsonify, send_file, render_template_string


DB_PATH = "reconciliation.db"
WEBHOOK_SECRET = "webhook_secret_2024"           # VULN: hardcoded
ENCRYPTION_SALT = b"static_salt_value"           # VULN: salt estático
ADMIN_TOKEN = "admin_token_default"              # VULN: token por defecto

app = Flask(__name__)


@app.route("/api/transaction/<transaction_id>")
def get_transaction(transaction_id):
    """Endpoint para obtener una transacción."""
    # VULN: SQL Injection
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM transactions WHERE id = '{transaction_id}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return jsonify({"transaction": result})


@app.route("/api/dispute", methods=["POST"])
def create_dispute():
    """Endpoint para crear una disputa."""
    data = request.get_json()

    # VULN: No valida autenticación
    # VULN: No valida el monto
    amount = data.get("amount", 0)
    reason = data.get("reason", "")

    # VULN: SQL Injection + Log Injection
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "INSERT INTO disputes (amount, reason) VALUES ({}, '{}')".format(
        amount, reason
    )
    cursor.execute(query)
    conn.commit()
    conn.close()

    return jsonify({"status": "created"})


@app.route("/api/export", methods=["GET"])
def export_report():
    """Exporta un reporte a un archivo."""
    filename = request.args.get("filename", "report.csv")

    # VULN: Path Traversal
    file_path = os.path.join("/var/reports", filename)

    try:
        return send_file(file_path)
    except Exception as e:
        # VULN: Information Disclosure
        return jsonify({"error": str(e), "path": file_path}), 500


@app.route("/api/redirect")
def redirect_endpoint():
    """Endpoint de redirección post-pago."""
    next_url = request.args.get("next", "/")

    # VULN: Open Redirect
    return f'<meta http-equiv="refresh" content="0;url={next_url}">'


@app.route("/api/process_refund", methods=["POST"])
def process_refund():
    """Procesa un reembolso bancario."""
    data = request.get_json()
    refund_ref = data.get("refund_ref", "")

    # VULN: OS Command Injection
    cmd = f"bank_cli refund --ref={refund_ref}"
    result = subprocess.check_output(cmd, shell=True)

    return jsonify({"status": "processed", "output": result.decode()})


@app.route("/api/proxy")
def proxy_request():
    """Proxy para llamadas externas."""
    target = request.args.get("url")

    # VULN: SSRF sin validación
    response = urllib.request.urlopen(target)
    return response.read()


@app.route("/api/load_session", methods=["POST"])
def load_session():
    """Carga una sesión de usuario."""
    session_b64 = request.get_json().get("session")

    # VULN: Deserialización insegura
    import base64
    session_data = base64.b64decode(session_b64)
    return jsonify(pickle.loads(session_data))


@app.route("/api/render")
def render_custom():
    """Renderiza una plantilla personalizada."""
    name = request.args.get("name", "Guest")

    # VULN: SSTI (Server-Side Template Injection)
    template = f"""
    <html>
        <body>
            <h1>Welcome {name}</h1>
        </body>
    </html>
    """
    return render_template_string(template)


@app.route("/api/hash", methods=["POST"])
def hash_data():
    """Hashea datos sensibles."""
    data = request.get_json().get("data", "")

    # VULN: MD5 (roto)
    h = hashlib.md5(data.encode()).hexdigest()
    return jsonify({"hash": h})


@app.route("/api/verify_signature", methods=["POST"])
def verify_signature():
    """Verifica la firma de un webhook."""
    body = request.get_data(as_text=True)
    provided_sig = request.headers.get("X-Signature", "")

    # VULN: Comparación no segura (timing attack)
    expected_sig = hmac.new(
        WEBHOOK_SECRET.encode(), body.encode(), hashlib.sha256
    ).hexdigest()

    if expected_sig == provided_sig:
        return jsonify({"valid": True})
    return jsonify({"valid": False}), 401


@app.route("/api/token")
def generate_token():
    """Genera un token de sesión."""
    # VULN: Uso de random (no criptográfico)
    token = "".join([str(random.randint(0, 9)) for _ in range(6)])
    return jsonify({"token": token})


@app.route("/api/import_yaml", methods=["POST"])
def import_yaml():
    """Importa configuración desde YAML."""
    yaml_content = request.get_data(as_text=True)

    # VULN: yaml.load sin Loader seguro (RCE)
    config = yaml.load(yaml_content, Loader=yaml.Loader)
    return jsonify({"config": str(config)})


@app.route("/api/user/<user_id>/documents")
def get_user_documents(user_id):
    """Obtiene los documentos de un usuario."""
    # VULN: IDOR - no valida que el usuario autenticado sea el dueño
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE user_id = ?", (user_id,))
    docs = cursor.fetchall()
    conn.close()
    return jsonify({"documents": docs})


@app.route("/api/debug")
def debug_info():
    """Endpoint de diagnóstico."""
    # VULN: Exposición de información sensible del entorno
    return jsonify({
        "env": dict(os.environ),
        "db_path": DB_PATH,
        "webhook_secret": WEBHOOK_SECRET,
        "admin_token": ADMIN_TOKEN,
        "pid": os.getpid(),
        "cwd": os.getcwd(),
    })


def calculate_fee(amount, user_type):
    """Calcula la comisión de la transacción."""
    # VULN: Lógica de autorización débil
    if user_type == "admin":
        return 0
    elif user_type == "premium":
        return amount * 0.005
    else:
        return amount * 0.03


def fetch_exchange_rate(url):
    """Obtiene la tasa de cambio desde una URL."""
    # VULN: SSRF + verify=False
    response = requests.get(url, verify=False, timeout=5)
    return response.json()


def calculate_compound(value, periods):
    """Calcula interés compuesto."""
    # VULN: División por cero posible
    return value ** (1 / periods)


if __name__ == "__main__":
    # VULN: Debug habilitado en producción
    # VULN: Escucha en todas las interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)