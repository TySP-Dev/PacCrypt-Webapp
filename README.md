<div align="center">

[![Main Repo](https://img.shields.io/badge/Main%20Repo-git.tysstech.com-blue?logo=gitea)](https://git.tysstech.com/TySS-Dev/PacCrypt-Webapp)
[![Mirror Repo](https://img.shields.io/badge/Mirror%20Repo-github.com-blue?logo=github)](https://github.com/TySP-Dev/PacCrypt-Webapp)
[![Official Instance](https://img.shields.io/website?url=https%3A%2F%2Fpaccrypt.tysstech.com&label=Official%20Instance)](https://paccrypt.tysstech.com)

</div>

# PacCrypt 🔐

**PacCrypt** is a modern, secure web application for encrypting and decrypting text and files using multiple encryption algorithms. Built with Flask and featuring a comprehensive REST API, modular encryption engines, and advanced security features including 2FA support.

> [!WARNING]
> Merged Dev branch into main, program is still in the development stage so no need to have multiple branches. Please submit issues for bugs. I expect a lot, I dont recall the state of the Dev branch.

> [!IMPORTANT]
> This document contains AI generated pieces that have not been reviewed yet.
> Next push will contain human oversite on the documentation.

---

## ✨ Features

### 🔒 **Multi-Algorithm Encryption**
- **AES-GCM**: Text encryption with authenticated encryption
- **AES-CBC**: Text and file encryption with HMAC authentication  
- **XChaCha20-Poly1305**: Modern stream cipher for text and files
- **RSA Hybrid**: RSA-4096 with AES hybrid encryption for text and files

### 🌐 **Comprehensive API**
- RESTful API endpoints for all encryption operations
- Text and file encryption/decryption
- Key pair generation for RSA hybrid
- PacShare file sharing with secure pickup URLs
- Full API documentation (see [API.md](API.md))

### 📁 **PacShare - Secure File Sharing**
- End-to-end encrypted file uploads
- Dual-password system (pickup + encryption)
- Optional 2FA with TOTP codes
- QR code generation for 2FA setup
- Automatic file expiration
- Secure pickup URLs with one-time download

### 🛡️ **Advanced Security**
- Admin panel with 2FA support
- Encrypted admin credentials and logs
- Secure session management
- PBKDF2 key derivation with 200,000 iterations
- Cryptographically secure random ID generation

### 🎮 **Built-in Entertainment**
- Hidden Pac-Man game (type `pacman` to play)
- Arrow key and swipe controls
- Retro gaming experience with authentic sounds

### 🧾 **Admin Control Panel**
- Real-time server monitoring and statistics
- GitHub auto-update functionality
- Upload management and cleanup
- Server restart capabilities
- Development/Production mode switching
- Comprehensive audit logging

### 📱 **Modern UI/UX**
- Fully responsive mobile design
- Smart UI state management
- Clipboard integration
- Visual feedback for all operations
- Custom error pages (403, 404, 500)
- SEO-optimized with sitemap and robots.txt

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **Git** (for updates and installation)
- **pip** package manager

### Installation

```bash
# Clone the repository
git clone -b "dev-only_DO-NOT-USE" https://github.com/TySP-Dev/PacCrypt-Webapp.git
cd PacCrypt-Webapp

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r application_data/requirements.txt
```

### Running the Application

#### Development Mode
```bash
# Linux/macOS
python application_data/control_scripts/start_dev.py

# Windows  
python application_data\control_scripts\start_dev.py
```

#### Production Mode
```bash
# Linux/macOS
python application_data/control_scripts/start_prod.py

# Windows
python application_data\control_scripts\start_prod.py
```

### Access the Application

- **Local access**: http://127.0.0.1:5000
- **Network access**: http://YOUR_IP_ADDRESS:5000
- **Admin setup**: http://127.0.0.1:5000/admin-setup (first-time only)

---

## 📖 Usage Guide

### 🔐 Text Encryption/Decryption

1. **Select Algorithm**: Choose from AES-GCM, AES-CBC, XChaCha20, or RSA Hybrid
2. **Enter Text**: Type or paste your message
3. **Set Password**: Enter a strong encryption password
4. **For RSA**: Generate key pair first if using RSA Hybrid
5. **Execute**: Click Encrypt/Decrypt
6. **Copy Result**: Use the copy button for easy sharing

### 📁 File Operations

1. **Upload File**: Select file using the file picker
2. **Choose Algorithm**: Pick AES-CBC, XChaCha20, or RSA Hybrid (AES-GCM not supported for files)
3. **Set Password**: Enter encryption password
4. **Process**: File will be encrypted/decrypted and downloaded automatically

### 📤 PacShare - Secure File Sharing

1. **Upload File**: Select file to share
2. **Set Passwords**: 
   - **Encryption Password**: Encrypts the file content
   - **Pickup Password**: Required to access the download page
3. **Optional 2FA**: Enable for additional security
4. **Share URL**: Copy the generated pickup URL
5. **Recipient Access**: They need both passwords (and 2FA code if enabled)

### 🎮 Hidden Pac-Man Game

- Type `pacman` in any text input
- Use arrow keys or swipe gestures to play
- Authentic retro gaming experience with sound effects

---

## 🛠️ Admin Panel

Access the admin panel at `/adminpage` after initial setup at `/admin-setup`.

### 🔑 Setup Process
1. Visit `/admin-setup` on first run
2. Create admin username and password
3. Optionally enable 2FA for enhanced security
4. Login at `/admin-login`

### 🎛️ Admin Features
- **📊 Server Monitoring**: Real-time statistics and uptime
- **🔄 Server Control**: Restart, switch dev/prod modes
- **📋 Route Management**: View all available endpoints
- **🔃 GitHub Integration**: Auto-update from repository
- **🧹 File Management**: Clear uploads and expired files
- **🔐 Security**: Change password, manage 2FA
- **📝 Audit Logs**: View encrypted activity logs
- **⚙️ Settings**: Configure upload limits and file retention

### 🔒 Security Features
- Encrypted credential storage
- TOTP-based 2FA support
- QR code generation for authenticator apps
- Secure session management
- Encrypted audit logging

---

## 🛡️ Deployment Tips
##### I recommend using Linux as the host server, the follow confs are Linux focused
The official PacCrypt host is **Arch** minimal install.

**HTTP** Nginx config (Not recommended):

```nginx
server {
    listen 80;
    server_name yourdomain.com; #<-- Your URL here

    # Basic Privacy-Respecting Logging
    access_log off; #<-- set to syslog:server=unix:/dev/log; for logging
    error_log syslog:server=unix:/dev/log crit; #<-- Currently set for only critical logs, remove crit for all logs

    # Hardened Proxy Settings
    location / {
        proxy_pass http://127.0.0.1:5000;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_http_version 1.1;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Basic Hardening Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "geolocation=(), microphone=()" always;

    # Prevent Abuse
    client_max_body_size 10M;
    keepalive_timeout 10;
    server_tokens off;
}
```

**HTTPS** Nginx config (Recommended):

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com; #<-- Your URL here

    # Basic Privacy-Respecting Logging
    access_log off; #<-- set to syslog:server=unix:/dev/log; for logging
	error_log syslog:server=unix:/dev/log crit; #<-- Currently set for only critical logs, remove crit for all logs

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS Server Block
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate path/to/yourdomain.com.cert; #<-- Could also be .cert.pem
    ssl_certificate_key path/to/yourdomain.com.key; #<-- Could also be .key.pem

    # SSL Hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Strong security headers (adjust as needed)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "geolocation=(), camera=()" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Basic Privacy-Respecting Logging
    access_log off; #<-- set to syslog:server=unix:/dev/log; for logging
	error_log syslog:server=unix:/dev/log crit; #<-- Currently set for only critical logs, remove crit for all logs

    client_max_body_size xG; #<-- Change to what the max upload for PacCrypt Share

    # Reverse proxy to Flask
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;

        # Comment these out if you want complete anonymity between client and app
        # proxy_set_header X-Real-IP $remote_addr;
        # proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # proxy_set_header X-Forwarded-Proto $scheme;

        # Optional privacy: strip identifying headers
        proxy_hide_header X-Powered-By;
    }
}
```
---

## 📋 API Integration

PacCrypt provides a comprehensive REST API for programmatic access. See the detailed [API Documentation](API.md) for:

- **Encryption Operations**: Text and file encryption/decryption
- **Key Management**: RSA key pair generation
- **PacShare Integration**: Programmatic file sharing
- **Algorithm Discovery**: List available encryption methods

### Quick API Example

```bash
# Encrypt text using AES-GCM
curl -X POST "https://paccrypt.unnaturalll.dev/api/encrypt" \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello World!", "password": "secret123", "algorithm": "aes_gcm"}'

# Upload file via PacShare
curl -X POST "https://paccrypt.unnaturalll.dev/api/pacshare" \
  -F "file=@document.pdf" \
  -F "enc_password=encrypt123" \
  -F "pickup_password=pickup123" \
  -F "algorithm=aes_cbc"
```

## 🗂️ Project Structure

```
PacCrypt-Webapp/
├── app.py                          # Main Flask application
├── README.md                       # This file
├── ROADMAP.md                     # Development roadmap
├── API.md                         # API documentation
├── application_data/              # Application configuration
│   ├── control_scripts/           # Server management scripts
│   │   ├── start_dev.py          # Development mode starter
│   │   ├── start_prod.py         # Production mode starter
│   │   ├── restart_dev.py        # Development restart
│   │   ├── restart_prod.py       # Production restart
│   │   └── stop.py               # Server stop script
│   ├── requirements.txt          # Python dependencies
│   ├── settings.json            # Application settings
│   ├── admin_creds.json         # Encrypted admin credentials
│   ├── admin_key.key           # Admin encryption key
│   └── admin_logs.enc          # Encrypted audit logs
├── paccrypt_algos/               # Encryption modules
│   ├── __init__.py              # Package initialization
│   ├── aes_cbc.py              # AES-CBC implementation
│   ├── aes_gcm.py              # AES-GCM implementation
│   ├── xchacha.py              # XChaCha20-Poly1305
│   └── rsa_hybrid.py           # RSA hybrid encryption
├── pacshare/                    # File upload storage
│   ├── *.encrypted             # Encrypted uploaded files
│   └── *.json                  # File metadata
├── templates/                   # HTML templates
│   ├── index.html              # Main interface
│   ├── pickup.html             # File pickup page
│   ├── admin*.html             # Admin panel pages
│   └── error pages (403,404,500)
└── static/                     # Static assets
    ├── css/styles.css          # Application styling
    ├── js/                     # JavaScript modules
    ├── img/                    # Images and icons
    ├── fonts/                  # Custom fonts
    └── audio/                  # Sound effects
```

---

## 🔒 Security Considerations

### ⚠️ Important Security Notes

- **Password Strength**: Use strong, unique passwords for all operations
- **2FA Recommended**: Enable 2FA for admin accounts and sensitive file shares
- **HTTPS Required**: Always use HTTPS in production environments
- **Regular Updates**: Keep dependencies updated for security patches
- **Backup Strategy**: Implement regular backups of encrypted data

### 🛡️ Encryption Details

- **AES-256**: Industry standard symmetric encryption
- **RSA-4096**: Strong asymmetric encryption for key exchange
- **PBKDF2**: 200,000 iterations for key derivation
- **Authenticated Encryption**: GCM and Poly1305 modes prevent tampering
- **Secure Random**: Cryptographically secure random number generation

## 🤝 Contributing

We welcome contributions! Please see our [ROADMAP.md](ROADMAP.md) for planned features and development priorities.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

- **Documentation**: See [API.md](API.md) for API details
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Element/Matrix Chat**: 
- **Official Instance**: N/A

---

## 📄 License

MIT

**🔐 Secure by design. Simple by choice. Powerful by nature.**



