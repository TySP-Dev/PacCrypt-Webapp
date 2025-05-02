# PacCrypt WebApp

**PacCrypt** is a secure, feature-rich web app for encrypting and decrypting text and files — built with Flask, JavaScript, and AES-GCM encryption.  
Now with an admin control panel, GitHub updater, and a built-in Pac-Man easter egg! 🕹️

Offically Hosted: [paccrypt.unnaturalll.dev](http://paccrypt.unnaturalll.dev)

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
- Git (for update feature)
- Nginx (recommended)

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
  ./start_dev.sh  # or start_dev.bat
  ```

- Production Mode:
  ```bash
  ./start_prod.sh  # or start_prod.bat
  ```

Visit [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🧭 Navigation & Usage

### 🔐 Encrypt & Decrypt

- Choose between Basic Cipher or Advanced AES
- Type your message or upload a file
- Enter password (if AES)
- Select mode using toggle (Encrypt/Decrypt)
- Hit Execute

### 📤 Share Files

- Upload a file with two passwords:
  - Encryption password
  - Pickup password
- Get a shareable URL and click 📋 Copy Link

### 🔑 Generate Passwords

- Click Generate
- Then hit 📋 Copy

### 🎮 Pac-Man Game

- Type `pacman` in the input box
- Game appears with Restart/Exit controls
- Classic arrow key controls 🕹️

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

Minimal Nginx config:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Use Let's Encrypt to add SSL/TLS support.

---

## 🗂️ Project Structure

```
paccrypt-webapp-final/
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
