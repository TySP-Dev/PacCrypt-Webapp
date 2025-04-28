## DEV DEV DEV

import os
from flask import Flask, render_template, request, jsonify
import html
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# ====== Your App Code ======

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

# ====== Smart Server Startup ======

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

if __name__ == "__main__":
    PRODUCTION = os.getenv("PRODUCTION", "false").lower() == "true"

    if PRODUCTION:
        from waitress import serve
        print("[INFO] Running in PRODUCTION mode with Waitress.")
        serve(app, host="0.0.0.0", port=5000)
    else:
        print("[INFO] Running in DEVELOPMENT mode with Flask server.")
        app.run(debug=True, host="0.0.0.0", port=5000)


## DEV DEV DEV
