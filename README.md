# PacCrypt

> [!IMPORTANT]
> PacCrypt is still in the beginning stages of development.
> PacCrypt has not been examined for vulnerabilities yet.
> Due to this, PacCrypt and PacShare are not recommended for PII or sensitive information.
> User discretion is advised.

**PacCrypt** is used for text encoding and decoding (using a basic Cypher), text and file encrypting and decrypting (using AES-GCM more algorithms coming) — built with Flask, JavaScript, and AES-GCM encryption.  
Built in admin control panel, GitHub updater, and a Pac-Man <ins>like</ins> game! 🕹️

---

> [!NOTE]
> Windows as a server host is not offically supported.
> Some features may not work, or work incorrectly, if hosted on Windows.
> It is recommended to host the server on Linux.
> PacCrypt Server has been tested on Debian and Arch.
> The official server is hosted using Debian.

## Features

- 🔒 Basic Cypher for Text
- 🔐 AES Encryption for Text & Files
- 📁 PacShare for Encrypted File Sharing
- 🔑 Random Password Generator
- 🎮 Pac-Man <ins>Like</ins> Game — type `pacman` into input
- 🧾 Admin Panel:
  - Site map with live route list
  - Server restart & GitHub update button
  - Admin credential management
  - Server logs & upload cleanup
  - Server Settings
- 📜 Error Landing Pages
- 📱 Mobile UI

---

## Installation

### Prerequisites

- Python 3.7+
- Flask 3+
- Cryptography 42+
- Waitress 2.1+
- Git
- Nginx (Recommended)

---

### ⚡ Quick Setup

```bash
git clone https://github.com/TySP-Dev/PacCrypt-Webapp.git
cd PacCrypt-Webapp
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Then run:

- Development Mode:
  ```bash
  ./start_dev.sh
  ```

- Production Mode:
  ```bash
  ./start_prod.sh
  ```

Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) or [http://localhost:5000](http://localhost:5000) - If you **are** on the host system<p/>
Visit http://hosts_private_ip - If you are **not** on the host system but on the same network<p/>
Visit http://hosts_public_ip:5000 - If you are **not** on the host system but on a different network

---

## Navigation & Usage

### 🔑 Generate Passwords

- Click Generate
- Boom a Password
- **Note:** This is also used as a seed generator for the Pac-Man <ins>like</ins> game

### 🔐 Encrypt & Decrypt

- Choose between Basic Cipher or Advanced AES
- Select mode using toggle (Encrypt/Decrypt)
- Type your message or upload a file
- Enter password (Advanced AES)
- Hit Execute
- Boom Encrypted/Decrypted Text/File

### 📤 Share Files

- Upload a file with two passwords:
  - Encryption password
  - Pickup password
- Get a shareable URL and click `Copy Link`

### 🎮 Pac-Man __like__ Game

- Type `pacman` in the input box
- Arrow key and Swipe controls
- Game restarts and a new seed is generated once all dots are gone

---

## 🛠️ Admin Panel

Visit `/adminpage`

> [!NOTE]
> You will be redirected to `/admin-setup` if you have not set a username and password yet.

Features:
- 🔄 Restart server
- 🔃 Update from GitHub (git pull)
- 🧽 Clear PacShare uploads
- 🔐 Change admin password
- 📝 View logs
- ⚙️ Adjust upload settings

---

## 🛡️ Deployment Tips
The official PacCrypt host is **Debian** minimal install.

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

## 🗂️ Project Structure

```
PacCrypt/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── index.html
│   ├── 404.html
│   └── 403.html
│   └── 500.html
│   └── admin.html
│   └── admin_login.html
│   └── admin_settings.html
│   └── admin_setup.html
│   └── pickup.html
├── static/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   └── ui.js
│   │   └── pacman.js
│   │   └── main.js
│   │   └── fileops.js
│   │   └── encryption.js
│   ├── img/
│   │   └── PacCrypt.png
│   │   └── Github_logo.png
│   │   └── sitemap.png
│   ├── fonts/
│   │   └── PressStart2P-Regular.ttf
│   └── audio/
│       └── chomp.mp3
├── start_dev.bat
├── start_prod.bat
├── start_dev.sh
├── start_prod.sh
```




