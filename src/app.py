"""Secure Notes API application after vulnerability remediation."""

import os
import re
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# ВИПРАВЛЕННЯ 1: Отримання ключа зі змінної оточення або криптостійка генерація
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24).hex()


def init_db():
    """Initialize SQLite database with sample records."""
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT, secret TEXT)"
    )
    cursor.execute("DELETE FROM notes")
    cursor.execute(
        "INSERT INTO notes (title, secret) VALUES ('Public Note', 'No secrets here')"
    )
    cursor.execute(
        "INSERT INTO notes (title, secret) VALUES ('Admin Backup', 'FLAG{SQL_INJECTION_SUCCESS}')"
    )
    conn.commit()
    conn.close()


@app.after_request
def add_security_headers(response):
    """Attach mandatory HTTP security headers to every response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


@app.route("/")
def index():
    """Return API status message."""
    return "Notes API is running securely."


@app.route("/search")
def search_notes():
    """Search notes safely using parameterized SQL queries."""
    query = request.args.get("q", "")
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    # ВИПРАВЛЕННЯ 2: Параметризований SQL-запит захищає від SQL-ін'єкцій
    cursor.execute("SELECT id, title FROM notes WHERE title LIKE ?", (f"%{query}%",))
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"results": rows})


@app.route("/ping")
def ping_host():
    """Validate host format and execute command safely without shell."""
    host = request.args.get("host", "localhost")
    # ВИПРАВЛЕННЯ 3: Білий список символів + вимкнення shell=True
    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return jsonify({"error": "Invalid host format"}), 400
    output = subprocess.check_output(
        ["cmd", "/c", "echo", "Checking host:", host], shell=False, text=True
    )
    return jsonify({"output": output.strip()})


if __name__ == "__main__":
    init_db()
    # ВИПРАВЛЕННЯ 4: Вимкнений режим debug у продакшені
    app.run(host="127.0.0.1", port=5000, debug=False)