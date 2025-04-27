from flask import Flask, render_template, request, jsonify
import html
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from waitress import serve

app = Flask(__name__)

# Basic Encoder/Decoder
ALPHABET = list('abcdefghijklmnopqrstuvwxyz')

def simple_encode(text: str) -> str:
    return ''.join(
        ALPHABET[(ALPHABET.index(c) + 3) % 26] if c in ALPHABET else c
        for c in text.lower()
    )

def simple_decode(text: str) -> str:
    return ''.join(
        ALPHABET[(ALPHABET.index(c) - 3) % 26] if c in ALPHABET else c
        for c in text.lower()
    )

# Advanced Encrypt/Decrypt using AES-GCM
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode())

def advanced_encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    encrypted = salt + nonce + ct
    return base64.urlsafe_b64encode(encrypted).decode()

def advanced_decrypt(token_b64: str, password: str) -> str:
    try:
        data = base64.urlsafe_b64decode(token_b64.encode())
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode()
    except Exception:
        return "[Error] Invalid password or corrupted data!"

# Combined Route for Page & AJAX
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == 'POST':
        data = request.get_json()
        encryption_type = data.get("encryption-type", "basic")
        operation = data.get("operation", "")
        message = data.get("message", "")
        password = data.get("password", "")
        file_password = data.get("file-password", "")

        final_password = file_password if file_password else password

        if encryption_type == "basic":
            result = simple_encode(message) if operation == "encrypt" else simple_decode(message)
        else:
            result = advanced_encrypt(message, final_password) if operation == "encrypt" else advanced_decrypt(message, final_password)

        return jsonify(result=html.escape(result))

    return render_template(
        "index.html",
        result="",
        password="",
        encryption_type="advanced"
    )

if __name__ == "__main__":
    # Use Waitress to serve the app in production
    serve(app, host="0.0.0.0", port=5000)
