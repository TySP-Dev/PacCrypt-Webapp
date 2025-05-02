# ===== Standard Library Imports =====
import os
import io
import json
import html
import base64
import hashlib
import secrets
import datetime
import subprocess
import platform
from datetime import UTC
import sys

# ===== Third-Party Imports =====
from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, flash, send_file
)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet

# ===== Application Configuration =====
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", os.urandom(24))

# ===== Constants =====
ADMIN_CRED_FILE = 'admin_creds.json'
ADMIN_KEY_FILE = 'admin_key.key'
ADMIN_LOG_FILE = 'admin_logs.enc'
SETTINGS_FILE = 'settings.json'
ALPHABET = list('abcdefghijklmnopqrstuvwxyz')

DEFAULT_SETTINGS = {
    "upload_folder": "uploads",
    "max_file_age_days": 14,
    "max_file_size_bytes": 25 * 1024 * 1024 * 1024  # 25GB
}

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

def simple_encode(text: str) -> str:
    """Basic Caesar cipher encryption."""
    return ''.join(ALPHABET[(ALPHABET.index(c) + 3) % 26] if c in ALPHABET else c for c in text.lower())

def simple_decode(text: str) -> str:
    """Basic Caesar cipher decryption."""
    return ''.join(ALPHABET[(ALPHABET.index(c) - 3) % 26] if c in ALPHABET else c for c in text.lower())

def advanced_encrypt(plaintext: str, password: str) -> str:
    """Encrypt text using AES-GCM with password-derived key."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(salt + nonce + ct).decode()

def advanced_decrypt(token_b64: str, password: str) -> str:
    """Decrypt text using AES-GCM with password-derived key."""
    try:
        data = base64.urlsafe_b64decode(token_b64.encode())
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        return AESGCM(key).decrypt(nonce, ct, None).decode()
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

def encrypt_creds(username, password):
    """Encrypt and store admin credentials."""
    key = load_admin_key()
    cipher = Fernet(key)
    salt = os.urandom(16)
    hashed_pw = hash_password(password, salt)
    data = json.dumps({"u": username, "p": hashed_pw, "s": base64.b64encode(salt).decode()}).encode()
    with open(ADMIN_CRED_FILE, 'wb') as f:
        f.write(cipher.encrypt(data))

def check_creds(username, password):
    """Verify admin credentials."""
    try:
        key = load_admin_key()
        cipher = Fernet(key)
        with open(ADMIN_CRED_FILE, 'rb') as f:
            decrypted = cipher.decrypt(f.read())
        creds = json.loads(decrypted)
        salt = base64.b64decode(creds["s"])
        return creds["u"] == username and creds["p"] == hash_password(password, salt)
    except Exception as e:
        print("[ERROR] check_creds failed:", e)
        return False

def log_admin_event(message: str):
    """Log admin actions securely."""
    try:
        key = load_admin_key()
        cipher = Fernet(key)
        timestamp = datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        encrypted = cipher.encrypt(f"[{timestamp}] {message}".encode())
        with open(ADMIN_LOG_FILE, 'ab') as f:
            f.write(encrypted + b"\n")
    except Exception as e:
        print("[ERROR] Failed to write admin log:", e)

# ===== File Management =====
def cleanup_expired_files():
    """Remove files older than MAX_FILE_AGE_DAYS."""
    try:
        now = datetime.datetime.now(UTC)
        for fname in os.listdir(UPLOAD_FOLDER):
            if fname.endswith(".enc") or fname.endswith(".json"):
                path = os.path.join(UPLOAD_FOLDER, fname)
                try:
                    file_time = datetime.datetime.fromtimestamp(os.path.getmtime(path), UTC)
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
    """Main application route handling encryption/decryption and file uploads."""
    if request.method == 'POST':
        if 'file' in request.files:
            return handle_file_upload(request)
        else:
            return handle_text_operation(request)
    return render_template("index.html", result="", password="", encryption_type="advanced", settings=settings)

def handle_file_upload(request):
    """Process file upload and encryption."""
    file = request.files['file']
    enc_password = request.form.get('enc_password')
    pickup_password = request.form.get('pickup_password')

    if not file or not enc_password or not pickup_password:
        return jsonify({"error": "Missing fields"}), 400

    if file.content_length and file.content_length > MAX_FILE_SIZE_BYTES:
        return jsonify({"error": f"File too large! Limit: {MAX_FILE_SIZE_BYTES / (1024**3):.2f} GB"}), 400

    filename = secure_filename(file.filename)
    temp_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(temp_path)

    with open(temp_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    key = derive_key(enc_password, salt)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)

    random_id = secrets.token_urlsafe(24)

    with open(os.path.join(UPLOAD_FOLDER, f"{random_id}.enc"), 'wb') as f:
        f.write(salt + nonce + ct)
    os.remove(temp_path)

    meta = {
        'pickup_password': base64.urlsafe_b64encode(hashlib.sha256(pickup_password.encode()).digest()).decode(),
        'original_name': filename,
        'timestamp': datetime.datetime.now(UTC).isoformat()
    }
    with open(os.path.join(UPLOAD_FOLDER, f"{random_id}.json"), 'w') as f:
        json.dump(meta, f)

    pickup_url = request.host_url.rstrip('/') + url_for('pickup_file', file_id=random_id)
    return jsonify({"success": True, "pickup_url": pickup_url})

def handle_text_operation(request):
    """Process text encryption/decryption operations."""
    data = request.get_json()
    encryption_type = data.get("encryption-type", "basic")
    operation = data.get("operation", "")
    message = data.get("message", "")
    password = data.get("password", "")

    if encryption_type == "basic":
        result = simple_encode(message) if operation == "encrypt" else simple_decode(message)
    else:
        result = advanced_encrypt(message, password) if operation == "encrypt" else advanced_decrypt(message, password)

    return jsonify(result=html.escape(result))

# ===== File Pickup Route =====
@app.route("/pickup/<file_id>", methods=["GET", "POST"])
def pickup_file(file_id):
    """Handle file pickup and decryption."""
    meta_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.json")
    enc_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.enc")

    if not os.path.exists(meta_path) or not os.path.exists(enc_path):
        flash("File not found or expired")
        return redirect(url_for('index'))

    if request.method == 'POST':
        return handle_file_pickup(request, meta_path, enc_path, file_id)
    return render_template("pickup.html", file_id=file_id)

def handle_file_pickup(request, meta_path, enc_path, file_id):
    """Process file pickup and decryption."""
    pickup_password = request.form.get('pickup_password')
    enc_password = request.form.get('enc_password')

    if not pickup_password or not enc_password:
        flash("Missing fields")
        return redirect(request.url)

    with open(meta_path, 'r') as f:
        meta = json.load(f)

    expected_hash = base64.urlsafe_b64encode(hashlib.sha256(pickup_password.encode()).digest()).decode()
    if expected_hash != meta['pickup_password']:
        flash("Incorrect pickup password")
        return redirect(request.url)

    with open(enc_path, 'rb') as f:
        enc_data = f.read()
    salt, nonce, ct = enc_data[:16], enc_data[16:28], enc_data[28:]
    key = derive_key(enc_password, salt)

    try:
        decrypted = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        flash("Decryption failed")
        return redirect(request.url)

    os.remove(meta_path)
    os.remove(enc_path)
    log_admin_event(f"File {file_id} downloaded and deleted.")

    response = send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=meta['original_name'],
        mimetype='application/octet-stream'
    )
    
    # Add headers for better mobile compatibility
    response.headers['Content-Disposition'] = f'attachment; filename="{meta["original_name"]}"'
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

# ===== Admin Routes =====
@app.route("/admin-logs")
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
def admin_settings():
    """Manage application settings."""
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

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

    updated_settings = {
        "upload_folder": upload_folder,
        "max_file_age_days": max_file_age_days,
        "max_file_size_bytes": max_file_size_bytes
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
        if u and p:
            encrypt_creds(u, p)
            session["admin_logged_in"] = True
            return redirect(url_for("admin_page"))
        flash("Both fields required")
    return render_template("admin_setup.html")

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    """Admin login handler."""
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        if check_creds(u, p):
            session["admin_logged_in"] = True
            log_admin_event("Admin login successful.")
            return redirect(url_for("admin_page"))
        else:
            log_admin_event("Admin login failed.")
            flash("Incorrect credentials")
    return render_template("admin_login.html")

@app.route("/admin-logout")
def admin_logout():
    """Admin logout handler."""
    session.pop("admin_logged_in", None)
    return redirect(url_for("index"))

@app.route("/adminpage")
def admin_page():
    """Admin dashboard."""
    if not session.get("admin_logged_in"):
        if not os.path.exists(ADMIN_CRED_FILE):
            return redirect(url_for("admin_setup"))
        return redirect(url_for("admin_login"))

    cleanup_expired_files()
    routes = [rule.rule for rule in app.url_map.iter_rules() if rule.endpoint != 'static']

    # Get uptime based on OS
    if platform.system() == "Windows":
        try:
            # Windows uptime using PowerShell
            ps_command = "(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime"
            uptime_output = subprocess.check_output(["powershell", "-Command", ps_command], shell=True).decode()
            # Convert the PowerShell DateTime to Python datetime
            boot_time = datetime.datetime.strptime(uptime_output.strip(), "%A, %B %d, %Y %I:%M:%S %p")
            # Make boot_time timezone-aware (assuming local time)
            boot_time = boot_time.replace(tzinfo=datetime.timezone.utc)
            current_time = datetime.datetime.now(UTC)
            uptime = current_time - boot_time
            uptime_str = f"{uptime.days} days, {uptime.seconds // 3600} hours, {(uptime.seconds % 3600) // 60} minutes"
        except Exception as e:
            print(f"[ERROR] Failed to get Windows uptime: {str(e)}")
            uptime_str = "Unavailable"
    else:
        try:
            # Try reading from /proc/uptime first
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                uptime_str = f"{days} days, {hours} hours, {minutes} minutes"
        except Exception:
            try:
                # Fallback to uptime command if /proc/uptime fails
                uptime_str = subprocess.check_output("uptime -p", shell=True).decode().strip()
            except Exception as e:
                print(f"[ERROR] Failed to get Linux uptime: {str(e)}")
                uptime_str = "Unavailable"

    server_info = {
        "uptime": uptime_str,
        "time": datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        "python": platform.python_version(),
        "debug": app.debug
    }

    return render_template("admin.html", routes=routes, server_info=server_info)

@app.route("/restart-server", methods=["POST"])
def restart_server():
    """Restart the server."""
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        if platform.system() == "Windows":
            # Get the current process ID
            current_pid = os.getpid()
            # Create a batch file to restart the server
            restart_script = f"""
            @echo off
            timeout /t 2 /nobreak
            start "" "python" "app.py"
            """
            with open("restart.bat", "w") as f:
                f.write(restart_script)
            
            # Start the restart script and exit
            subprocess.Popen(["restart.bat"], shell=True)
            return jsonify({"message": "Server restart initiated"}), 200
        else:
            # For Linux/Unix systems, use a Python-based restart
            # Get the current Python interpreter and script path
            python_path = sys.executable
            script_path = os.path.abspath(__file__)
            
            # Create a shell script to restart the server
            restart_script = f"""#!/bin/bash
            sleep 2
            {python_path} {script_path}
            """
            
            # Write and make the script executable
            with open("restart.sh", "w") as f:
                f.write(restart_script)
            os.chmod("restart.sh", 0o755)
            
            # Start the restart script and exit
            subprocess.Popen(["./restart.sh"], shell=True)
            return jsonify({"message": "Server restart initiated"}), 200
    except Exception as e:
        print(f"[ERROR] Failed to restart server: {str(e)}")
        return jsonify({"error": f"Failed to restart server: {str(e)}"}), 500

@app.route("/admin-reset", methods=["POST"])
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

@app.route("/admin-clear-uploads", methods=["POST"])
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