"""
Módulo de conciliación bancaria - Versión 3.

Sistema de conciliación de transacciones y gestión de disputas.
"""
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import urllib.request
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, request, jsonify, send_file, render_template_string
from werkzeug.utils import secure_filename


DB_PATH = "reconciliation.db"
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
ENCRYPTION_SALT = os.environ.get("ENCRYPTION_SALT", "").encode()
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

app = Flask(__name__)


def _is_admin():
    if not ADMIN_TOKEN:
        return False
    provided = request.headers.get("X-Admin-Token", "")
    return hmac.compare_digest(provided, ADMIN_TOKEN)


def _is_safe_url(next_url):
    parsed = urlparse(next_url)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return False
    if parsed.netloc and parsed.netloc != request.host:
        return False
    return True


def _is_safe_remote_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = info[4][0]
        ip_obj = ipaddress.ip_address(ip)
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
                ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified):
            return False
    return True


@app.route("/api/transaction/<transaction_id>")
def get_transaction(transaction_id):
    """Endpoint para obtener una transacción."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "SELECT * FROM transactions WHERE id = ?"
    cursor.execute(query, (transaction_id,))
    result = cursor.fetchone()
    conn.close()
    return jsonify({"transaction": result})


@app.route("/api/dispute", methods=["POST"])
def create_dispute():
    """Endpoint para crear una disputa."""
    if not _is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400
    reason = str(data.get("reason", ""))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "INSERT INTO disputes (amount, reason) VALUES (?, ?)"
    cursor.execute(query, (amount, reason))
    conn.commit()
    conn.close()

    return jsonify({"status": "created"})


@app.route("/api/export", methods=["GET"])
def export_report():
    """Exporta un reporte a un archivo."""
    filename = secure_filename(request.args.get("filename", "report.csv"))
    base_dir = "/var/reports"
    file_path = os.path.realpath(os.path.join(base_dir, filename))

    if not file_path.startswith(os.path.realpath(base_dir) + os.sep):
        return jsonify({"error": "Invalid filename"}), 400

    try:
        return send_file(file_path)
    except Exception:
        return jsonify({"error": "File not found"}), 500


@app.route("/api/redirect")
def redirect_endpoint():
    """Endpoint de redirección post-pago."""
    next_url = request.args.get("next", "/")
    if not _is_safe_url(next_url):
        next_url = "/"

    return f'<meta http-equiv="refresh" content="0;url={html.escape(next_url)}">'


@app.route("/api/process_refund", methods=["POST"])
def process_refund():
    """Procesa un reembolso bancario."""
    data = request.get_json()
    refund_ref = data.get("refund_ref", "")

    if not re.fullmatch(r"[A-Za-z0-9-]+", refund_ref):
        return jsonify({"error": "Invalid refund reference"}), 400

    result = subprocess.check_output(
        ["bank_cli", "refund", f"--ref={refund_ref}"], shell=False
    )

    return jsonify({"status": "processed", "output": result.decode()})


@app.route("/api/proxy")
def proxy_request():
    """Proxy para llamadas externas."""
    target = request.args.get("url")
    if not target or not _is_safe_remote_url(target):
        return jsonify({"error": "Invalid URL"}), 400

    response = urllib.request.urlopen(target)
    return response.read()


@app.route("/api/load_session", methods=["POST"])
def load_session():
    """Carga una sesión de usuario."""
    session_b64 = request.get_json().get("session")

    session_data = base64.b64decode(session_b64)
    return jsonify(json.loads(session_data.decode()))


@app.route("/api/render")
def render_custom():
    """Renderiza una plantilla personalizada."""
    name = request.args.get("name", "Guest")

    template = """
    <html>
        <body>
            <h1>Welcome {{ name }}</h1>
        </body>
    </html>
    """
    return render_template_string(template, name=name)


@app.route("/api/hash", methods=["POST"])
def hash_data():
    """Hashea datos sensibles."""
    data = request.get_json().get("data", "")

    h = hashlib.sha256(data.encode()).hexdigest()
    return jsonify({"hash": h})


@app.route("/api/verify_signature", methods=["POST"])
def verify_signature():
    """Verifica la firma de un webhook."""
    body = request.get_data(as_text=True)
    provided_sig = request.headers.get("X-Signature", "")

    expected_sig = hmac.new(
        WEBHOOK_SECRET.encode(), body.encode(), hashlib.sha256
    ).hexdigest()

    if hmac.compare_digest(expected_sig, provided_sig):
        return jsonify({"valid": True})
    return jsonify({"valid": False}), 401


@app.route("/api/token")
def generate_token():
    """Genera un token de sesión."""
    token = secrets.token_urlsafe(32)
    return jsonify({"token": token})


@app.route("/api/import_yaml", methods=["POST"])
def import_yaml():
    """Importa configuración desde YAML."""
    yaml_content = request.get_data(as_text=True)

    config = yaml.safe_load(yaml_content)
    return jsonify({"config": str(config)})


@app.route("/api/user/<user_id>/documents")
def get_user_documents(user_id):
    """Obtiene los documentos de un usuario."""
    authenticated_user = request.headers.get("X-User-Id")
    if authenticated_user != user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE user_id = ?", (user_id,))
    docs = cursor.fetchall()
    conn.close()
    return jsonify({"documents": docs})


@app.route("/api/debug")
def debug_info():
    """Endpoint de diagnóstico."""
    if not _is_admin():
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"status": "ok"})


def calculate_fee(amount, user_type):
    """Calcula la comisión de la transacción."""
    if user_type == "admin":
        if not _is_admin():
            return amount * 0.03
        return 0
    elif user_type == "premium":
        return amount * 0.005
    else:
        return amount * 0.03


def fetch_exchange_rate(url):
    """Obtiene la tasa de cambio desde una URL."""
    if not _is_safe_remote_url(url):
        raise ValueError("Invalid URL")
    response = requests.get(url, timeout=5)
    return response.json()


def calculate_compound(value, periods):
    """Calcula interés compuesto."""
    if periods == 0:
        raise ValueError("periods must be non-zero")
    return value ** (1 / periods)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)