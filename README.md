# PacCrypt WebApp

**PacCrypt** is a web-based platform that allows you to securely encrypt/decrypt text and files, generate passwords, and even enjoy a hidden Pac-Man game!  
Built using Python (Flask), JavaScript, and AES-GCM encryption.

Official Website: [paccrypt.unnaturalll.dev](http://paccrypt.unnaturalll.dev)

---

## ✨ Features

- 🔒 **Basic and Advanced Encryption** (Text and Files)
- 🔑 **Password Generator**
- 🄹️ **Pac-Man Easter Egg** (Type `pacman` to unlock!)
- 📱 **Responsive Design** (Mobile Friendly)
- ⚡ **One-Click Start Scripts** (Dev and Production modes)
- 🎨 **Modern Animated UI** (Dark Mode + Green Neon Theme)

---

## 👨‍💻 Installation

### 📋 Prerequisites

- **Python 3.7+**
- **Flask 3+**
- **Cryptography 42+**
- **Waitress 2.1+**
- **Nginx** (Recommended for production)

---

### ⚡ Quick Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/TySP-Dev/PacCrypt.git
   cd paccrypt-webapp-final
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. Install required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the app:

   **Windows**:
   ```bash
   start_dev.bat     # For Development
   start_prod.bat    # For Production
   ```

   **Linux / Mac**:
   ```bash
   chmod +x start_dev.sh start_prod.sh
   ./start_dev.sh    # For Development
   ./start_prod.sh   # For Production
   ```

5. Access the app at:  
   [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🚀 Usage Guide

### 🔒 Text Encryption/Decryption

- Select **Encryption Type** (Basic or Advanced)
- Enter text
- Provide password (Advanced only)
- Choose **Encrypt** or **Decrypt**
- Click **Submit**

### 📁 File Encryption/Decryption

- Select **Advanced** encryption
- Upload a file
- Provide password
- Choose **Encrypt** or **Decrypt**
- Click **Submit**

### 🔑 Password Generator

- Click **Generate** to create a secure password
- Click **Copy** to save it to clipboard

### 🎮 Pac-Man Easter Egg

- Type **`pacman`** into the input box to unlock the hidden Pac-Man game!

---

## 🛡️ Hosting with Nginx (optional)

Recommended for secure public deployment.

Example minimal Nginx config:

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

> Tip: Set up SSL with Let's Encrypt for HTTPS security! 🔐

---

## 📂 Project Structure

```
paccrypt-webapp-final/
├── app.py
├── requirements.txt
├── templates/
│   ├── index.html
│   ├── 404.html
│   └── 403.html
│   └── 500.html
├── static/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   └── script.js
│   ├── img/
│   │   └── PacCrypt.png
│   └── audio/
│       └── chomp.mp3
├── start_dev.bat
├── start_prod.bat
├── start_dev.sh
├── start_prod.sh
├── README.md
```

---

## 🤝 Contributing

Contributions are welcome!

- Add new features
- Fix bugs
- Improve performance
- Expand the Pac-Man Easter Egg 🎮

---

## 📄 License

This project is licensed under the **MIT License**.

---