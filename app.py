# ===== Standard Library Imports =====
import os
import io
import json
import html
import base64
import hashlib
import secrets
import subprocess
import platform
from datetime import datetime
import sys
import psutil
from flask_cors import CORS
from io import BytesIO
import ipaddress
from functools import wraps
import time
from collections import defaultdict
from datetime import datetime, timedelta
import clamd

# ===== Third-Party Imports =====
from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, flash, send_file, make_response
)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import pyotp
import qrcode
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ===== PacCrypt Algorithm Imports =====
from paccrypt_algos import aes_cbc, aes_gcm, xchacha, rsa_hybrid
# Post-quantum crypto removed for simplicity

# ===== Application Configuration =====
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", os.urandom(24))
CORS(app, origins=["https://pdf.unnaturalll.dev"])

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)
limiter.init_app(app)

# Session timeout configuration
app.permanent_session_lifetime = timedelta(minutes=30)  # 30 minute timeout

# ===== Constants =====
ADMIN_CRED_FILE = 'application_data/admin_creds.json'
ADMIN_KEY_FILE = 'application_data/admin_key.key'
ADMIN_LOG_FILE = 'application_data/admin_logs.enc'
SETTINGS_FILE = 'application_data/settings.json'

DEFAULT_SETTINGS = {
    "upload_folder": "pacshare",
    "max_file_age_days": 14,
    "max_file_size_bytes": 25 * 1024 * 1024 * 1024,  # 25GB
    "admin_ip_whitelist": [],  # Empty list means all IPs allowed
    "virus_scanning_enabled": True,
    "session_timeout_minutes": 30,
    "rate_limit_per_minute": 60,
    "rate_limit_per_hour": 1000
}

# ===== Available Encryption Algorithms =====
AVAILABLE_ALGORITHMS = {
    "aes_cbc": {
        "name": "AES-CBC",
        "module": aes_cbc,
        "supports_text": True,
        "supports_file": True,
        "description": "AES-256 with CBC mode and HMAC authentication"
    },
    "aes_gcm": {
        "name": "AES-GCM", 
        "module": aes_gcm,
        "supports_text": True,
        "supports_file": False,
        "description": "AES-256 with GCM mode (authenticated encryption)"
    },
    "xchacha": {
        "name": "XChaCha20-Poly1305",
        "module": xchacha,
        "supports_text": True,
        "supports_file": True,
        "description": "XChaCha20 stream cipher with Poly1305 authentication"
    },
    "rsa_hybrid": {
        "name": "RSA Hybrid",
        "module": rsa_hybrid,
        "supports_text": True,
        "supports_file": True,
        "description": "RSA-4096 with AES hybrid encryption",
        "requires_keypair": True
    }
}

# Post-quantum algorithms removed

# ===== Settings Management =====
def load_settings():
    """Load application settings from file or create with defaults."""
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(DEFAULT_SETTINGS, f)
    with open(SETTINGS_FILE, 'r') as f:
        return json.load(f)

settings = load_settings()
UPLOAD_FOLDER = settings["upload_folder"]
MAX_FILE_AGE_DAYS = settings["max_file_age_days"]
MAX_FILE_SIZE_BYTES = settings["max_file_size_bytes"]

# Ensure upload folder exists and has proper permissions
if not os.path.exists(UPLOAD_FOLDER):
    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        # Set permissions to 755 (rwxr-xr-x)
        os.chmod(UPLOAD_FOLDER, 0o755)
        print(f"[INFO] Created upload directory: {UPLOAD_FOLDER}")
    except Exception as e:
        print(f"[ERROR] Failed to create upload directory: {str(e)}")
        raise

# ===== Cryptographic Functions =====
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from password using PBKDF2."""
    return PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=200_000).derive(password.encode())

def hash_password(password: str, salt: bytes) -> str:
    """Hash a password with salt for secure storage."""
    return base64.urlsafe_b64encode(derive_key(password, salt)).decode()

def advanced_encrypt(plaintext: str, password: str) -> str:
    """Encrypt plaintext with AES-GCM and return base64-encoded result."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(salt + nonce + ciphertext).decode()

def advanced_decrypt(data_b64: str, password: str) -> str:
    """Decrypt base64-encoded AES-GCM encrypted data."""
    try:
        data = base64.b64decode(data_b64)
        salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        return "[Error] Invalid password or corrupted data!"

# ===== Admin Authentication =====
def load_admin_key():
    """Load or generate admin encryption key."""
    if not os.path.exists(ADMIN_KEY_FILE):
        with open(ADMIN_KEY_FILE, 'wb') as f:
            f.write(Fernet.generate_key())
    with open(ADMIN_KEY_FILE, 'rb') as f:
        return f.read()

def encrypt_creds(username, password, totp_secret=None):
    """Encrypt and store admin credentials."""
    key = load_admin_key()
    cipher = Fernet(key)
    salt = os.urandom(16)
    hashed_pw = hash_password(password, salt)
    data = {
        "u": username, 
        "p": hashed_pw, 
        "s": base64.b64encode(salt).decode(),
        "totp_secret": totp_secret,
        "2fa_enabled": totp_secret is not None
    }
    with open(ADMIN_CRED_FILE, 'wb') as f:
        f.write(cipher.encrypt(json.dumps(data).encode()))

def check_creds(username, password, totp_code=None):
    """Verify admin credentials."""
    try:
        key = load_admin_key()
        cipher = Fernet(key)
        with open(ADMIN_CRED_FILE, 'rb') as f:
            decrypted = cipher.decrypt(f.read())
        creds = json.loads(decrypted)
        salt = base64.b64decode(creds["s"])
        
        # Check username and password first
        if not (creds["u"] == username and creds["p"] == hash_password(password, salt)):
            return False
            
        # Check 2FA if enabled
        if creds.get("2fa_enabled", False):
            if not totp_code:
                return False
            totp_secret = creds.get("totp_secret")
            if not totp_secret:
                return False
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                return False
                
        return True
    except Exception as e:
        print("[ERROR] check_creds failed:", e)
        return False

def get_admin_2fa_status():
    """Check if admin has 2FA enabled."""
    try:
        key = load_admin_key()
        cipher = Fernet(key)
        with open(ADMIN_CRED_FILE, 'rb') as f:
            decrypted = cipher.decrypt(f.read())
        creds = json.loads(decrypted)
        return creds.get("2fa_enabled", False)
    except Exception:
        return False

def get_admin_totp_secret():
    """Get admin TOTP secret for QR code generation."""
    try:
        key = load_admin_key()
        cipher = Fernet(key)
        with open(ADMIN_CRED_FILE, 'rb') as f:
            decrypted = cipher.decrypt(f.read())
        creds = json.loads(decrypted)
        return creds.get("totp_secret")
    except Exception:
        return None

def log_admin_event(message: str):
    """Log admin actions securely."""
    try:
        key = load_admin_key()
        cipher = Fernet(key)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        encrypted = cipher.encrypt(f"[{timestamp}] {message}".encode())
        with open(ADMIN_LOG_FILE, 'ab') as f:
            f.write(encrypted + b"\n")
    except Exception as e:
        print("[ERROR] Failed to write admin log:", e)

# ===== Security Functions =====
def check_ip_whitelist(ip_address):
    """Check if IP address is in admin whitelist."""
    whitelist = settings.get("admin_ip_whitelist", [])
    if not whitelist:  # Empty list means all IPs allowed
        return True

    try:
        client_ip = ipaddress.ip_address(ip_address)
        for allowed_ip in whitelist:
            if '/' in allowed_ip:  # CIDR notation
                if client_ip in ipaddress.ip_network(allowed_ip, strict=False):
                    return True
            else:  # Single IP
                if client_ip == ipaddress.ip_address(allowed_ip):
                    return True
        return False
    except ValueError:
        return False

def admin_required(f):
    """Decorator to require admin authentication and IP whitelist check."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session timeout
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))

        # Check if session has expired
        if 'login_time' in session:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.now() - login_time > timedelta(minutes=settings.get("session_timeout_minutes", 30)):
                session.clear()
                log_admin_event(f"Session expired for IP {request.remote_addr}")
                return redirect(url_for('admin_login'))

        # Check IP whitelist
        if not check_ip_whitelist(request.remote_addr):
            log_admin_event(f"Unauthorized IP access attempt: {request.remote_addr}")
            return jsonify({"error": "Access denied: IP not whitelisted"}), 403

        return f(*args, **kwargs)
    return decorated_function

def scan_file_for_viruses(file_path):
    """Scan file for viruses using ClamAV."""
    if not settings.get("virus_scanning_enabled", True):
        return True, "Virus scanning disabled"

    try:
        cd = clamd.ClamdUnixSocket()
        # Test connection
        cd.ping()

        # Scan file
        result = cd.scan(file_path)
        if result is None:
            return True, "File is clean"

        # If infected
        for file, status in result.items():
            if status[0] == 'FOUND':
                return False, f"Virus detected: {status[1]}"

        return True, "File is clean"

    except clamd.ConnectionError:
        # ClamAV daemon not running
        log_admin_event("ClamAV daemon not available - virus scanning skipped")
        return True, "ClamAV not available - scan skipped"
    except Exception as e:
        log_admin_event(f"Virus scan error: {str(e)}")
        return True, f"Scan error: {str(e)}"

def check_session_timeout():
    """Check if admin session has timed out."""
    if 'admin_logged_in' in session and 'login_time' in session:
        login_time = datetime.fromisoformat(session['login_time'])
        if datetime.now() - login_time > timedelta(minutes=settings.get("session_timeout_minutes", 30)):
            session.clear()
            return True
    return False

# ===== File Management =====
def cleanup_expired_files():
    """Remove files older than MAX_FILE_AGE_DAYS."""
    try:
        now = datetime.now()
        for fname in os.listdir(UPLOAD_FOLDER):
            if fname.endswith(".enc") or fname.endswith(".json"):
                path = os.path.join(UPLOAD_FOLDER, fname)
                try:
                    file_time = datetime.datetime.fromtimestamp(os.path.getmtime(path), )
                    age = (now - file_time).days
                    if age > MAX_FILE_AGE_DAYS:
                        os.remove(path)
                        print(f"[INFO] Deleted expired file: {fname}")
                except Exception as e:
                    print(f"[ERROR] Could not check/delete file {fname}: {e}")
    except Exception as e:
        print(f"[ERROR] Failed to cleanup expired files: {str(e)}")

# ===== Route Handlers =====
@app.route("/", methods=["GET", "POST"])
def index():
    """Main application route handling file uploads."""
    if request.method == 'POST':
        if 'file' in request.files:
            return handle_file_upload(request)
        else:
            return jsonify(error="Use /api/encrypt or /api/decrypt endpoints for text operations"), 400
    return render_template("index.html", settings=settings)

def handle_file_upload(request):
    """Process file upload and encryption."""
    file = request.files['file']
    enc_password = request.form.get('enc_password')
    pickup_password = request.form.get('pickup_password')
    algorithm = request.form.get('algorithm', 'aes_cbc')  # Default to AES-CBC
    enable_2fa = request.form.get('enable_2fa') == 'on'  # Check if 2FA checkbox is checked

    if not file or not enc_password or not pickup_password:
        return jsonify({"error": "Missing fields"}), 400

    if file.content_length and file.content_length > MAX_FILE_SIZE_BYTES:
        return jsonify({"error": f"File too large! Limit: {MAX_FILE_SIZE_BYTES / (1024**3):.2f} GB"}), 400

    # Validate algorithm
    if algorithm not in AVAILABLE_ALGORITHMS:
        return jsonify({"error": "Invalid algorithm"}), 400
        
    algo_config = AVAILABLE_ALGORITHMS[algorithm]
    if not algo_config["supports_file"]:
        return jsonify({"error": "Algorithm does not support file operations"}), 400

    filename = secure_filename(file.filename)
    temp_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(temp_path)

    # Virus scan the uploaded file
    is_clean, scan_message = scan_file_for_viruses(temp_path)
    if not is_clean:
        os.remove(temp_path)  # Remove infected file
        log_admin_event(f"Virus detected in upload: {filename} - {scan_message}")
        return jsonify({"error": f"File rejected: {scan_message}"}), 400

    log_admin_event(f"File uploaded and scanned: {filename} - {scan_message}")

    try:
        # Use the selected algorithm for encryption
        module = algo_config["module"]
        
        random_id = secrets.token_urlsafe(24)
        encrypted_filename = f"{random_id}.{algorithm}.encrypted"
        encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        
        # Encrypt file using the correct API (in_path, out_path, password)
        module.encrypt_file(temp_path, encrypted_path, enc_password)
        os.remove(temp_path)

        meta = {
            'pickup_password': base64.urlsafe_b64encode(hashlib.sha256(pickup_password.encode()).digest()).decode(),
            'original_name': encrypt_filename(filename, enc_password),
            'algorithm': algorithm,  # Store algorithm used for decryption
            'timestamp': datetime.now().isoformat(),
            'require_2fa': enable_2fa
        }
        
        # Generate TOTP secret if 2FA is enabled
        if enable_2fa:
            totp_secret = pyotp.random_base32()
            meta['totp_secret'] = totp_secret
            meta['service_name'] = f"PacCrypt File: {filename[:20]}..."
        with open(os.path.join(UPLOAD_FOLDER, f"{random_id}.json"), 'w') as f:
            json.dump(meta, f)

        pickup_url = request.host_url.rstrip('/') + url_for('pickup_file', file_id=random_id)
        response_data = {"success": True, "pickup_url": pickup_url}
        
        # If 2FA is enabled, also return QR code URL for immediate setup
        if enable_2fa:
            qr_url = request.host_url.rstrip('/') + url_for('generate_qr_code', file_id=random_id)
            response_data["qr_code_url"] = qr_url
            response_data["totp_secret"] = totp_secret
            response_data["service_name"] = f"PacCrypt File: {filename[:20]}..."
            
        return jsonify(response_data)
    except Exception as e:
        # Clean up temp file if it still exists
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500


def encrypt_filename(filename: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, filename.encode(), None)
    return base64.urlsafe_b64encode(salt + nonce + ct).decode()

def decrypt_filename(enc_filename_b64: str, password: str) -> str:
    raw = base64.urlsafe_b64decode(enc_filename_b64)
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None).decode()

# ===== File Pickup Route =====
@app.route("/pickup/<file_id>", methods=["GET", "POST"])
def pickup_file(file_id):
    """Handle file pickup and decryption."""
    meta_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.json")
    
    # Find the encrypted file (could have different algorithm extensions)
    enc_path = None
    for filename in os.listdir(UPLOAD_FOLDER):
        if filename.startswith(f"{file_id}.") and filename.endswith(".encrypted"):
            enc_path = os.path.join(UPLOAD_FOLDER, filename)
            break
    
    # Fallback to old .enc format for backward compatibility
    if not enc_path:
        old_enc_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.enc")
        if os.path.exists(old_enc_path):
            enc_path = old_enc_path

    if not os.path.exists(meta_path) or not enc_path or not os.path.exists(enc_path):
        flash("File not found or expired")
        return redirect(url_for('index'))

    if request.method == 'POST':
        return handle_file_pickup(request, meta_path, enc_path, file_id)
    
    # Check if 2FA is required for this file
    require_2fa = False
    service_name = None
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            meta = json.load(f)
            require_2fa = meta.get('require_2fa', False)
            if require_2fa:
                service_name = meta.get('service_name', 'PacCrypt File')
    
    return render_template("pickup.html", file_id=file_id, require_2fa=require_2fa, service_name=service_name)

def handle_file_pickup(request, meta_path, enc_path, file_id):
    """Process file pickup and decryption."""
    pickup_password = request.form.get('pickup_password')
    enc_password = request.form.get('enc_password')
    totp_code = request.form.get('totp_code')

    if not pickup_password or not enc_password:
        flash("Missing fields")
        return redirect(request.url)

    with open(meta_path, 'r') as f:
        meta = json.load(f)

    expected_hash = base64.urlsafe_b64encode(hashlib.sha256(pickup_password.encode()).digest()).decode()
    if expected_hash != meta['pickup_password']:
        flash("Incorrect pickup password")
        return redirect(request.url)

    # Check 2FA if required
    if meta.get('require_2fa', False):
        if not totp_code:
            flash("2FA code is required")
            return redirect(request.url)
        
        totp_secret = meta.get('totp_secret')
        if not totp_secret:
            flash("2FA configuration error")
            return redirect(request.url)
        
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1):  # Allow 1 window tolerance for clock drift
            flash("Invalid 2FA code")
            return redirect(request.url)

    # Check if this is an algorithm-based encryption or legacy AESGCM
    algorithm = meta.get('algorithm')
    
    try:
        if algorithm and algorithm in AVAILABLE_ALGORITHMS:
            # Use the new algorithm-based decryption
            algo_config = AVAILABLE_ALGORITHMS[algorithm]
            module = algo_config["module"]
            
            # Create temporary file for decryption
            temp_dec_path = os.path.join(UPLOAD_FOLDER, f"temp_decrypt_{secrets.token_urlsafe(8)}")
            try:
                # Decrypt file using the correct API (in_path, out_path, password)
                module.decrypt_file(enc_path, temp_dec_path, enc_password)
                
                # Read decrypted data
                with open(temp_dec_path, 'rb') as f:
                    decrypted = f.read()
            finally:
                # Clean up temp file
                if os.path.exists(temp_dec_path):
                    os.remove(temp_dec_path)
        else:
            # Legacy AESGCM decryption for backward compatibility
            with open(enc_path, 'rb') as f:
                enc_data = f.read()
            salt, nonce, ct = enc_data[:16], enc_data[16:28], enc_data[28:]
            key = derive_key(enc_password, salt)
            decrypted = AESGCM(key).decrypt(nonce, ct, None)
            
    except Exception as e:
        flash(f"Decryption failed: {str(e)}")
        return redirect(request.url)

    # Clean up files after successful decryption
    os.remove(meta_path)
    os.remove(enc_path)
    log_admin_event(f"File {file_id} downloaded and deleted.")

    try:
        original_name = decrypt_filename(meta['original_name'], enc_password)
    except Exception:
        original_name = "retrieved_file"

    response = send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=original_name,
        mimetype='application/octet-stream'
    )
    
    # Add headers for better mobile compatibility
    response.headers['Content-Disposition'] = f'attachment; filename="{original_name}"'
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

# ===== 2FA QR Code Routes =====
@app.route("/admin-qr")
@admin_required
def admin_qr_code():
    """Generate QR code for admin 2FA setup."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    
    totp_secret = get_admin_totp_secret()
    if not totp_secret:
        return "2FA not enabled for admin", 400
    
    # Generate TOTP URI for QR code
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name="admin",
        issuer_name="PacCrypt Admin"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to BytesIO
    img_buffer = BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    response = make_response(img_buffer.getvalue())
    response.headers['Content-Type'] = 'image/png'
    response.headers['Content-Disposition'] = 'inline; filename="admin_2fa_qr.png"'
    return response

@app.route("/qr/<file_id>")
def generate_qr_code(file_id):
    """Generate QR code for 2FA setup."""
    meta_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.json")
    
    if not os.path.exists(meta_path):
        return "File not found", 404
    
    with open(meta_path, 'r') as f:
        meta = json.load(f)
    
    if not meta.get('require_2fa', False):
        return "2FA not enabled for this file", 400
    
    totp_secret = meta.get('totp_secret')
    service_name = meta.get('service_name', 'PacCrypt File')
    
    if not totp_secret:
        return "TOTP secret not found", 400
    
    # Generate TOTP URI for QR code
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=file_id,
        issuer_name=service_name
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to BytesIO
    img_buffer = BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    response = make_response(img_buffer.getvalue())
    response.headers['Content-Type'] = 'image/png'
    response.headers['Content-Disposition'] = f'inline; filename="{file_id}_qr.png"'
    return response

# ===== Admin Routes =====
@app.route("/admin-logs")
@admin_required
def admin_logs():
    """View admin activity logs."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    logs = []
    try:
        key = load_admin_key()
        cipher = Fernet(key)
        if os.path.exists(ADMIN_LOG_FILE):
            with open(ADMIN_LOG_FILE, 'rb') as f:
                lines = f.readlines()
            for line in lines[-100:]:
                if line.strip():
                    try:
                        decrypted = cipher.decrypt(line.strip())
                        logs.append(decrypted.decode())
                    except Exception:
                        logs.append("[Error] Corrupted log entry.")
    except Exception as e:
        logs.append(f"[Error loading logs] {str(e)}")

    return jsonify(logs=logs)

@app.route("/admin-settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    """Manage application settings."""
    current_settings = load_settings()

    if request.method == 'POST':
        return handle_settings_update(request, current_settings)
    return render_template("admin_settings.html", settings=current_settings)

def handle_settings_update(request, current_settings):
    """Process settings update request."""
    upload_folder = request.form.get('upload_folder', current_settings.get('upload_folder', 'uploads'))
    max_file_age_days = int(request.form.get('max_file_age_days', current_settings.get('max_file_age_days', 14)))
    max_file_size_gb = float(request.form.get('max_file_size_gb', current_settings.get('max_file_size_bytes', 25 * 1024 * 1024 * 1024) / (1024 * 1024 * 1024)))
    max_file_size_bytes = int(max_file_size_gb * 1024 * 1024 * 1024)

    # Security settings
    session_timeout_minutes = int(request.form.get('session_timeout_minutes', current_settings.get('session_timeout_minutes', 30)))
    virus_scanning_enabled = request.form.get('virus_scanning_enabled') == 'on'

    # IP whitelist (one per line)
    ip_whitelist_text = request.form.get('admin_ip_whitelist', '')
    admin_ip_whitelist = [ip.strip() for ip in ip_whitelist_text.split('\n') if ip.strip()]

    updated_settings = {
        "upload_folder": upload_folder,
        "max_file_age_days": max_file_age_days,
        "max_file_size_bytes": max_file_size_bytes,
        "admin_ip_whitelist": admin_ip_whitelist,
        "virus_scanning_enabled": virus_scanning_enabled,
        "session_timeout_minutes": session_timeout_minutes,
        "rate_limit_per_minute": current_settings.get("rate_limit_per_minute", 60),
        "rate_limit_per_hour": current_settings.get("rate_limit_per_hour", 1000)
    }

    with open(SETTINGS_FILE, 'w') as f:
        json.dump(updated_settings, f)

    flash("Settings updated successfully!")

    global settings, UPLOAD_FOLDER, MAX_FILE_AGE_DAYS, MAX_FILE_SIZE_BYTES
    settings = load_settings()
    UPLOAD_FOLDER = settings.get('upload_folder', 'uploads')
    MAX_FILE_AGE_DAYS = settings.get('max_file_age_days', 14)
    MAX_FILE_SIZE_BYTES = settings.get('max_file_size_bytes', 25 * 1024 * 1024 * 1024)

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    return redirect(url_for("admin_settings"))

@app.route("/admin-setup", methods=["GET", "POST"])
def admin_setup():
    """Initial admin account setup."""
    if os.path.exists(ADMIN_CRED_FILE):
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        enable_2fa = request.form.get("enable_2fa") == "on"
        if u and p:
            totp_secret = pyotp.random_base32() if enable_2fa else None
            encrypt_creds(u, p, totp_secret)
            session["admin_logged_in"] = True
            session["admin_2fa_setup"] = enable_2fa
            return redirect(url_for("admin_page"))
        flash("Both fields required")
    return render_template("admin_setup.html")

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    """Admin login handler."""
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        totp_code = request.form.get("totp_code")
        
        # Check IP whitelist first
        if not check_ip_whitelist(request.remote_addr):
            log_admin_event(f"Login attempt from unauthorized IP: {request.remote_addr}")
            flash("Access denied: IP not authorized")
            return render_template("admin_login.html", requires_2fa=get_admin_2fa_status())

        if check_creds(u, p, totp_code):
            session["admin_logged_in"] = True
            session["login_time"] = datetime.now().isoformat()
            session.permanent = True  # Enable session timeout
            log_admin_event(f"Admin login successful from IP {request.remote_addr}")
            return redirect(url_for("admin_page"))
        else:
            log_admin_event("Admin login failed.")
            flash("Incorrect credentials or 2FA code")
    
    # Check if 2FA is enabled for the UI
    requires_2fa = get_admin_2fa_status()
    return render_template("admin_login.html", requires_2fa=requires_2fa)

@app.route("/admin-logout")
def admin_logout():
    """Admin logout handler."""
    session.pop("admin_logged_in", None)
    return redirect(url_for("index"))

@app.route("/adminpage")
@admin_required
def admin_page():
    """Admin dashboard."""
    cleanup_expired_files()
    routes = [rule.rule for rule in app.url_map.iter_rules() if rule.endpoint != 'static']

    now = datetime.now()
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())

        uptime = now - boot_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes = remainder // 60
        uptime_str = f"{days} days, {hours} hours, {minutes} minutes"
    except Exception as e:
        print(f"[ERROR] Uptime calculation failed: {e}")
        uptime_str = "Unavailable"

    server_info = {
        "uptime": uptime_str,
        "server_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "python_version": platform.python_version(),
        "debug_mode": app.debug
    }

    # Get 2FA status for UI
    tfa_enabled = get_admin_2fa_status()

    return render_template("admin.html", routes=routes, server_info=server_info, tfa_enabled=tfa_enabled)



@app.route("/restart-server", methods=["POST"])
def restart_server():
    """Restart the server."""
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        if platform.system() == "Windows":
            current_pid = os.getpid()
            restart_script = f"""
            @echo off
            timeout /t 2 /nobreak
            taskkill /F /PID {current_pid}
            set PRODUCTION=true
            start "" "python" "app.py"
            """
            with open("restart.bat", "w") as f:
                f.write(restart_script)
            subprocess.Popen(["restart.bat"], shell=True)
            return jsonify({"message": "Server restart initiated"}), 200
        else:
            current_pid = os.getpid()
            python_path = sys.executable
            script_path = os.path.abspath(__file__)

            # Create a safer and cleaner restart script
            restart_script = """#!/bin/bash
sleep 2
PID=$1
kill "$PID"
while kill -0 "$PID" 2>/dev/null; do sleep 0.5; done
export PRODUCTION=true
exec "$2" "$3"
"""

            with open("restart.sh", "w") as f:
                f.write(restart_script)
            os.chmod("restart.sh", 0o755)

            subprocess.Popen(["./restart.sh", str(current_pid), python_path, script_path])
            return jsonify({"message": "Server restart initiated"}), 200

    except Exception as e:
        print(f"[ERROR] Failed to restart server: {str(e)}")
        return jsonify({"error": f"Failed to restart server: {str(e)}"}), 500

@app.route("/admin-reset", methods=["POST"])
@admin_required
def admin_reset():
    """Reset admin credentials."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    try:
        if os.path.exists(ADMIN_CRED_FILE):
            os.remove(ADMIN_CRED_FILE)
        if os.path.exists(ADMIN_KEY_FILE):
            os.remove(ADMIN_KEY_FILE)
        session.pop("admin_logged_in", None)
        flash("Admin credentials reset. Please create new credentials.")
    except Exception as e:
        flash("Failed to reset admin credentials.")
        print("[ERROR] admin_reset failed:", e)
    return redirect(url_for("admin_setup"))

@app.route("/admin-change-password", methods=["POST"])
@admin_required
def admin_change_password():
    """Change admin password."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    current = request.form.get("current_password")
    new = request.form.get("new_password")

    try:
        key = load_admin_key()
        cipher = Fernet(key)
        with open(ADMIN_CRED_FILE, 'rb') as file:
            decrypted = cipher.decrypt(file.read())
        creds = json.loads(decrypted)

        salt = base64.b64decode(creds["s"])
        if hash_password(current, salt) != creds["p"]:
            flash("Current password is incorrect")
            return redirect(url_for("admin_page"))

        creds["p"] = hash_password(new, salt)
        encrypted = cipher.encrypt(json.dumps(creds).encode())
        with open(ADMIN_CRED_FILE, 'wb') as file:
            file.write(encrypted)

        log_admin_event("Admin password changed.")
        flash("Password updated successfully", "password-feedback")
        return redirect(url_for("admin_page"))

    except Exception as e:
        flash("Failed to update password")
        print("[ERROR] Password change failed:", e)
        return redirect(url_for("admin_page"))

@app.route("/admin-enable-2fa", methods=["POST"])
@admin_required
def admin_enable_2fa():
    """Enable 2FA for admin account."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    try:
        key = load_admin_key()
        cipher = Fernet(key)
        with open(ADMIN_CRED_FILE, 'rb') as file:
            decrypted = cipher.decrypt(file.read())
        creds = json.loads(decrypted)

        # Generate new TOTP secret
        totp_secret = pyotp.random_base32()
        creds["totp_secret"] = totp_secret
        creds["2fa_enabled"] = True

        encrypted = cipher.encrypt(json.dumps(creds).encode())
        with open(ADMIN_CRED_FILE, 'wb') as file:
            file.write(encrypted)

        log_admin_event("Admin 2FA enabled.")
        flash("2FA enabled successfully. Scan the QR code with your authenticator app.", "2fa-feedback")
        return redirect(url_for("admin_page"))

    except Exception as e:
        flash("Failed to enable 2FA")
        print("[ERROR] 2FA enable failed:", e)
        return redirect(url_for("admin_page"))

@app.route("/admin-disable-2fa", methods=["POST"])
@admin_required
def admin_disable_2fa():
    """Disable 2FA for admin account."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    totp_code = request.form.get("totp_code")
    if not totp_code:
        flash("2FA code required to disable 2FA")
        return redirect(url_for("admin_page"))

    try:
        key = load_admin_key()
        cipher = Fernet(key)
        with open(ADMIN_CRED_FILE, 'rb') as file:
            decrypted = cipher.decrypt(file.read())
        creds = json.loads(decrypted)

        # Verify 2FA code before disabling
        if creds.get("2fa_enabled", False):
            totp_secret = creds.get("totp_secret")
            if totp_secret:
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(totp_code, valid_window=1):
                    flash("Invalid 2FA code")
                    return redirect(url_for("admin_page"))

        creds["totp_secret"] = None
        creds["2fa_enabled"] = False

        encrypted = cipher.encrypt(json.dumps(creds).encode())
        with open(ADMIN_CRED_FILE, 'wb') as file:
            file.write(encrypted)

        log_admin_event("Admin 2FA disabled.")
        flash("2FA disabled successfully", "2fa-feedback")
        return redirect(url_for("admin_page"))

    except Exception as e:
        flash("Failed to disable 2FA")
        print("[ERROR] 2FA disable failed:", e)
        return redirect(url_for("admin_page"))

@app.route("/admin-clear-uploads", methods=["POST"])
@admin_required
def admin_clear_uploads():
    """Clear all uploaded files."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    deleted = 0
    for filename in os.listdir(UPLOAD_FOLDER):
        if filename.endswith(".enc") or filename.endswith(".json"):
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, filename))
                deleted += 1
            except Exception as e:
                print("[ERROR] Failed to delete:", filename, e)

    flash(f"Cleared {deleted} uploaded file(s).", "clear-feedback") 
    return redirect(url_for("admin_page"))

@app.route("/admin-update-server", methods=["POST"])
@admin_required
def admin_update_server():
    """Update server from GitHub repository."""
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        # Get the absolute path of the current directory
        current_dir = os.path.abspath(os.path.dirname(__file__))
        
        # Try to find git executable
        git_paths = [
            "/usr/bin/git",  # Standard Debian path
            "/usr/local/bin/git",
            "/bin/git",
            "git"  # Fallback to PATH
        ]
        
        git_cmd = None
        for path in git_paths:
            if os.path.exists(path) or path == "git":
                try:
                    # Test if git is executable
                    subprocess.run([path, "--version"], check=True, capture_output=True)
                    git_cmd = path
                    break
                except Exception:
                    continue

        if not git_cmd:
            return jsonify({"error": "Git executable not found. Please ensure git is installed and accessible."}), 500

        # Try to find the git repository by checking parent directories
        repo_dir = current_dir
        max_depth = 5  # Limit how far up we'll look
        found_git = False
        
        for _ in range(max_depth):
            git_dir = os.path.join(repo_dir, ".git")
            if os.path.exists(git_dir):
                found_git = True
                break
            parent_dir = os.path.dirname(repo_dir)
            if parent_dir == repo_dir:  # We've reached the root directory
                break
            repo_dir = parent_dir

        if not found_git:
            return jsonify({
                "error": "Git repository not found. Current directory: " + current_dir,
                "details": "Please ensure the application is running from within the git repository directory."
            }), 400

        # Execute git commands with proper error handling
        try:
            # Fetch latest changes
            fetch_result = subprocess.run([git_cmd, "fetch"], cwd=repo_dir, check=True, capture_output=True, text=True)
            
            # Reset to origin/main
            reset_result = subprocess.run([git_cmd, "reset", "--hard", "origin/main"], cwd=repo_dir, check=True, capture_output=True, text=True)
            
            # Pull latest changes
            pull_result = subprocess.run([git_cmd, "pull"], cwd=repo_dir, check=True, capture_output=True, text=True)
            
            return jsonify({
                "message": "Server updated successfully from GitHub!",
                "details": {
                    "fetch": fetch_result.stdout,
                    "reset": reset_result.stdout,
                    "pull": pull_result.stdout
                }
            }), 200
        except subprocess.CalledProcessError as e:
            error_msg = f"Git operation failed: {e.stderr if e.stderr else e.stdout}"
            print(f"[ERROR] {error_msg}")
            return jsonify({"error": error_msg}), 500

    except Exception as e:
        error_msg = f"Update failed: {str(e)}"
        print(f"[ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@app.route("/admin-switch-dev-mode", methods=["POST"])
@admin_required
def admin_switch_dev_mode():
    """Switch server to development mode."""
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        script_path = os.path.join(os.path.dirname(__file__), "application_data", "control_scripts", "restart_dev.py")
        
        if not os.path.exists(script_path):
            return jsonify({"error": "Development restart script not found"}), 404
        
        # Execute the restart script
        subprocess.Popen(["python", script_path])
        
        return jsonify({"message": "Switching to development mode... Server will restart momentarily."}), 200
    except Exception as e:
        error_msg = f"Failed to switch to dev mode: {str(e)}"
        print(f"[ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@app.route("/admin-switch-prod-mode", methods=["POST"])
@admin_required
def admin_switch_prod_mode():
    """Switch server to production mode."""
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        script_path = os.path.join(os.path.dirname(__file__), "application_data", "control_scripts", "restart_prod.py")
        
        if not os.path.exists(script_path):
            return jsonify({"error": "Production restart script not found"}), 404
        
        # Execute the restart script
        subprocess.Popen(["python", script_path])
        
        return jsonify({"message": "Switching to production mode... Server will restart momentarily."}), 200
    except Exception as e:
        error_msg = f"Failed to switch to prod mode: {str(e)}"
        print(f"[ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

# ===== Sitemap and Robots =====
@app.route("/sitemap", methods=["GET"])
def sitemap():
    """Generate sitemap.xml."""
    sitemap_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://paccrypt.unnaturalll.dev/</loc></url>
  <url><loc>https://paccrypt.unnaturalll.dev/pickup</loc></url>
  <url><loc>https://paccrypt.unnaturalll.dev/adminpage</loc></url>
  <url><loc>https://paccrypt.unnaturalll.dev/sitemap</loc></url>
</urlset>'''
    return sitemap_xml, 200, {'Content-Type': 'application/xml'}

@app.route("/robots.txt")
def robots_txt():
    """Generate robots.txt."""
    lines = [
        "User-agent: *",
        "Disallow: /adminpage",
        "Disallow: /admin-login",
        "Disallow: /admin-setup",
        "Disallow: /admin-reset",
        "Disallow: /admin-settings",
        "Disallow: /restart-server",
        "Disallow: /pickup",
        "Disallow: /admin-change-password",
        "Allow: /",
        f"Sitemap: {url_for('sitemap', _external=True)}"
    ]
    return "\n".join(lines), 200, {"Content-Type": "text/plain"}

# ===== API Endpoints =====
@app.route("/api/algorithms", methods=["GET"])
@limiter.limit("100 per minute")
def api_algorithms():
    """Get list of available encryption algorithms."""
    algorithms = {}
    for key, config in AVAILABLE_ALGORITHMS.items():
        algorithms[key] = {
            "name": config["name"],
            "description": config["description"],
            "supports_text": config["supports_text"],
            "supports_file": config["supports_file"],
            "requires_keypair": config.get("requires_keypair", False)
        }
    return jsonify(algorithms=algorithms)

@app.route("/api/generate-keypair", methods=["POST"])
@limiter.limit("10 per minute")
def api_generate_keypair():
    """Generate RSA key pair for hybrid algorithms."""
    try:
        data = request.get_json()
        algorithm = data.get("algorithm", "rsa_hybrid")
        
        if algorithm not in AVAILABLE_ALGORITHMS:
            return jsonify({"error": "Invalid algorithm"}), 400
            
        if not AVAILABLE_ALGORITHMS[algorithm].get("requires_keypair"):
            return jsonify({"error": "Algorithm does not require key pairs"}), 400
        
        module = AVAILABLE_ALGORITHMS[algorithm]["module"]
        private_key, public_key = module.generate_key_pair()
        
        return jsonify({
            "private_key": private_key.decode() if isinstance(private_key, bytes) else private_key,
            "public_key": public_key.decode() if isinstance(public_key, bytes) else public_key
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/encrypt", methods=["POST"])
@limiter.limit("30 per minute")
def api_encrypt():
    try:
        # Text encryption
        if request.is_json:
            data = request.get_json()
            message = data.get("message", "")
            password = data.get("password", "")
            algorithm = data.get("algorithm", "aes_gcm")
            public_key = data.get("public_key", "")
            
            if not message:
                return jsonify({"error": "Missing message"}), 400
            
            if algorithm not in AVAILABLE_ALGORITHMS:
                return jsonify({"error": "Invalid algorithm"}), 400
                
            algo_config = AVAILABLE_ALGORITHMS[algorithm]
            if not algo_config["supports_text"]:
                return jsonify({"error": "Algorithm does not support text operations"}), 400
            
            module = algo_config["module"]
            
            if algo_config.get("requires_keypair"):
                if not public_key:
                    return jsonify({"error": "Public key required for this algorithm"}), 400
                encrypted = module.encrypt_text(message, public_key, algorithm.replace("_hybrid", ""))
            else:
                if not password:
                    return jsonify({"error": "Password required"}), 400
                encrypted = module.encrypt_text(message, password)

            return jsonify({"result": encrypted, "algorithm": algorithm})

        # File encryption
        if "file" in request.files and "enc_password" in request.form:
            uploaded_file = request.files["file"]
            password = request.form["enc_password"]
            algorithm = request.form.get("algorithm", "aes_cbc")
            
            if algorithm not in AVAILABLE_ALGORITHMS:
                return jsonify({"error": "Invalid algorithm"}), 400
                
            algo_config = AVAILABLE_ALGORITHMS[algorithm]
            if not algo_config["supports_file"]:
                return jsonify({"error": "Algorithm does not support file operations"}), 400

            file_data = uploaded_file.read()
            temp_in = f"temp_in_{secrets.token_urlsafe(8)}"
            temp_out = f"temp_out_{secrets.token_urlsafe(8)}"
            
            try:
                with open(temp_in, 'wb') as f:
                    f.write(file_data)
                
                module = algo_config["module"]
                module.encrypt_file(temp_in, temp_out, password)
                
                with open(temp_out, 'rb') as f:
                    encrypted_data = f.read()
                
                output_filename = f"{uploaded_file.filename}.{algorithm}.encrypted"
                
                return send_file(
                    BytesIO(encrypted_data),
                    as_attachment=True,
                    download_name=output_filename,
                    mimetype="application/octet-stream"
                )
            finally:
                for temp_file in [temp_in, temp_out]:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)

        return jsonify({"error": "Missing or invalid input"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/decrypt", methods=["POST"])
@limiter.limit("30 per minute")
def api_decrypt():
    try:
        # Text decryption
        if request.is_json:
            data = request.get_json()
            encrypted_b64 = data.get("message", "")
            password = data.get("password", "")
            algorithm = data.get("algorithm", "aes_gcm")
            private_key = data.get("private_key", "")
            
            if not encrypted_b64:
                return jsonify({"error": "Missing encrypted message"}), 400
            
            if algorithm not in AVAILABLE_ALGORITHMS:
                return jsonify({"error": "Invalid algorithm"}), 400
                
            algo_config = AVAILABLE_ALGORITHMS[algorithm]
            if not algo_config["supports_text"]:
                return jsonify({"error": "Algorithm does not support text operations"}), 400
            
            module = algo_config["module"]
            
            if algo_config.get("requires_keypair"):
                if not private_key:
                    return jsonify({"error": "Private key required for this algorithm"}), 400
                plaintext = module.decrypt_text(encrypted_b64, private_key)
            else:
                if not password:
                    return jsonify({"error": "Password required"}), 400
                plaintext = module.decrypt_text(encrypted_b64, password)

            return jsonify({"result": plaintext})

        # File decryption
        if "file" in request.files and "enc_password" in request.form:
            uploaded_file = request.files["file"]
            password = request.form["enc_password"]
            
            # Try to determine algorithm from filename
            filename = uploaded_file.filename
            algorithm = "aes_cbc"  # default
            
            for algo_name in AVAILABLE_ALGORITHMS.keys():
                if f".{algo_name}.encrypted" in filename:
                    algorithm = algo_name
                    break
            
            # Allow override
            algorithm = request.form.get("algorithm", algorithm)
            
            if algorithm not in AVAILABLE_ALGORITHMS:
                return jsonify({"error": "Invalid algorithm"}), 400
                
            algo_config = AVAILABLE_ALGORITHMS[algorithm]
            if not algo_config["supports_file"]:
                return jsonify({"error": "Algorithm does not support file operations"}), 400

            encrypted_data = uploaded_file.read()
            temp_in = f"temp_in_{secrets.token_urlsafe(8)}"
            temp_out = f"temp_out_{secrets.token_urlsafe(8)}"
            
            try:
                with open(temp_in, 'wb') as f:
                    f.write(encrypted_data)
                
                module = algo_config["module"]
                module.decrypt_file(temp_in, temp_out, password)
                
                with open(temp_out, 'rb') as f:
                    decrypted_data = f.read()
                
                # Clean up filename
                if f".{algorithm}.encrypted" in filename:
                    filename = filename.replace(f".{algorithm}.encrypted", "")
                elif filename.endswith(".encrypted"):
                    filename = filename[:-10]
                else:
                    filename = f"decrypted_{filename}"
                
                return send_file(
                    BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=filename,
                    mimetype="application/octet-stream"
                )
            finally:
                for temp_file in [temp_in, temp_out]:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)

        return jsonify({"error": "Missing or invalid input"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/pacshare", methods=["POST"])
@limiter.limit("10 per minute")
def api_pacshare():
    try:
        enc_password = request.form.get("enc_password")
        pickup_password = request.form.get("pickup_password")
        algorithm = request.form.get("algorithm", "aes_cbc")  # Default to AES-CBC
        enable_2fa = request.form.get("enable_2fa") == "on"  # Check if 2FA checkbox is checked
        file = request.files.get("file")

        if not file or not enc_password or not pickup_password:
            return jsonify({"error": "Missing file or fields"}), 400

        # Validate algorithm
        if algorithm not in AVAILABLE_ALGORITHMS:
            return jsonify({"error": "Invalid algorithm"}), 400
            
        algo_config = AVAILABLE_ALGORITHMS[algorithm]
        if not algo_config["supports_file"]:
            return jsonify({"error": "Algorithm does not support file operations"}), 400

        filename = secure_filename(file.filename)
        temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{secrets.token_urlsafe(8)}_{filename}")
        file.save(temp_path)

        try:
            # Use the selected algorithm for encryption
            module = algo_config["module"]
            
            file_id = secrets.token_urlsafe(24)
            encrypted_filename = f"{file_id}.{algorithm}.encrypted"
            enc_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
            meta_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.json")
            
            # Encrypt file using the correct API (in_path, out_path, password)
            module.encrypt_file(temp_path, enc_path, enc_password)

            encrypted_filename = encrypt_filename(filename, enc_password)

            meta = {
                'pickup_password': base64.urlsafe_b64encode(
                    hashlib.sha256(pickup_password.encode()).digest()
                ).decode(),
                'original_name': encrypted_filename,
                'algorithm': algorithm,  # Store algorithm used for decryption
                'timestamp': datetime.now().isoformat(),
                'require_2fa': enable_2fa
            }
            
            # Generate TOTP secret if 2FA is enabled
            if enable_2fa:
                totp_secret = pyotp.random_base32()
                meta['totp_secret'] = totp_secret
                meta['service_name'] = f"PacCrypt File: {filename[:20]}..."

            with open(meta_path, "w") as f:
                json.dump(meta, f)

            pickup_url = request.host_url.rstrip('/') + url_for('pickup_file', file_id=file_id)
            response_data = {"pickup_url": pickup_url}
            
            # If 2FA is enabled, also return QR code URL for immediate setup
            if enable_2fa:
                qr_url = request.host_url.rstrip('/') + url_for('generate_qr_code', file_id=file_id)
                response_data["qr_code_url"] = qr_url
                response_data["totp_secret"] = totp_secret
                response_data["service_name"] = f"PacCrypt File: {filename[:20]}..."
                
            return jsonify(response_data)

        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== Error Handlers =====
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(405)
def method_not_allowed(e):
    return render_template('403.html'), 403

@app.errorhandler(FileNotFoundError)
def handle_file_not_found(e):
    if os.getenv("PRODUCTION", "false").lower() == "true":
        return render_template('500.html'), 500
    else:
        raise e

# ===== Application Entry Point =====
if __name__ == "__main__":
    PRODUCTION = os.getenv("PRODUCTION", "false").lower() == "true"
    if PRODUCTION:
        from waitress import serve
        print("[INFO] Running in PRODUCTION mode with Waitress.")
        serve(app, host="0.0.0.0", port=5000)
    else:
        print("[INFO] Running in DEVELOPMENT mode with Flask server.")
        app.run(debug=True, host="0.0.0.0", port=5000)

