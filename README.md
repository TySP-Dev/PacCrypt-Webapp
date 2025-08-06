# PacCrypt

**PacCrypt** is a secure, feature-rich web app for encrypting and decrypting text and files — built with Flask, JavaScript, and AES-GCM encryption.  
Now with an admin control panel, GitHub updater, and a built-in Pac-Man easter egg! 🕹️

---

## ✨ Features

- 🔒 Basic and Advanced Encryption for Text & Files
- 📁 Secure File Uploads with Pickup Passwords
- 🔑 Random Password Generator
- 🎮 Hidden Pac-Man Game — type `pacman` to play
- 🧠 Smart UI: Auto-switches input sections, toggles encryption labels
- 📋 Clipboard Copy Feedback with styled status boxes
- 🧾 Admin Panel:
  - Site map with live route list
  - Server restart & GitHub update button
  - Secure admin credential management
  - Server logs & upload cleanup
- 🧩 System Settings Page for upload config
- 📜 Custom 403, 404, and 500 Error Pages
- 🤖 robots.txt and /sitemap for crawlers
- 📱 Mobile-Responsive UI

---

## 👨‍💻 Installation

### 📋 Prerequisites

- Python 3.7+
- Flask 3+
- Cryptography 42+
- Waitress 2.1+
- Git (For update feature)
- Nginx (Recommended)
- Cockpit (Recommended if hosted on **Linux**)

---

### ⚡ Quick Setup

```bash
git clone https://github.com/TySP-Dev/PacCrypt.git
cd paccrypt-webapp-final
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Then run:

- Development Mode:
  ```bash
  ./start_dev.sh  #<-- start_dev.bat (Windows)
  ```

- Production Mode:
  ```bash
  ./start_prod.sh  #<-- start_prod.bat (Windows)
  ```

Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) or [http://localhost:5000](http://localhost:5000) - *If* you **are** on the host system
Visit http://hosts_private_ip - *If* you are **not** on the host system

---

## 🧭 Navigation & Usage

### 🔑 Generate Passwords

- Click Generate
- Then hit `📋 Copy Password`
- **Note:** This is also used as a seed generator for the Pac-Man *like* game

### 🔐 Encrypt & Decrypt

- Choose between Basic Cipher or Advanced AES
- Select mode using toggle (Encrypt/Decrypt)
- Type your message or upload a file
- Enter password (Advanced AES)
- Hit Execute
- Then hit `📋 Copy Output`

### 📤 Share Files

- Upload a file with two passwords:
  - Encryption password
  - Pickup password
- Get a shareable URL and click `📋 Copy Link`

### 🎮 Pac-Man *like* Game

- Type `pacman` in the input box
- Game appears with `Restart` and `Exit` buttons
- Arrow key and Swipe controls 🕹️
- Game restarts and a new seed is generated once all dots are eaten

---

## 🛠️ Admin Panel

Visit `/adminpage` after setting up credentials at `/admin-setup`.

Features:
- 🔄 Restart server
- 🔃 Update from GitHub (git pull)
- 🧽 Clear uploads
- 🔐 Change admin password
- 📝 View logs
- ⚙️ Adjust upload settings

---

## 🛡️ Deployment Tips
##### I recommend using Linux as the host server, the follow confs are Linux focused
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

---

## 📄 License

MIT © [TySP-Dev](https://github.com/TySP-Dev)

