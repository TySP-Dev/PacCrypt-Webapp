> [!IMPORTANT]
> Fully modular code for encryption libraries, ensure metadata is stored as encrypted hashs for PacShare, Revamp PacShares secure file send and pickup, and create a CLI and local application (Linux and Android).

---

### Phase 0

- [x] ~~Remove docker files (Dropping official docker support)~~

- [ ] Readd docker support

- [x] Update README.md to be current.

- [x] Add roadmap.md to repo

- [x] Create /application_data/ folder (for server settings, admin login and creds)

- [x] Create scripts folder in /application_data/

- [x] Create /paccrypt_algos/ folder

- [x] Builder better start, stop and restart scripts both prod and dev (Cross-platform: Windows & Linux)

- [x] Add a button in the admin panel to switch to and from prod and dev modes - **COMPLETED: `/admin-switch-dev-mode` and `/admin-switch-prod-mode` endpoints implemented**

### Phase 1: app.py - Modular Python Web App

##### app.py Responsibilities

- [x] Flask app + routing

- [x] Handle:
- [x] /encrypt (via API endpoints)
- [x] /decrypt (via API endpoints)  
- [x] /pickup/<file_id>

- [x] Receive:
- [x] File or text
- [x] pickup_password (required)
- [x] encryption_password (required)
- [x] encryption_mode (algorithm selection implemented)

- [x] Encrypt metadata using pickup password

- [x] Encrypt file using encryption password

- [x] Dynamically load correct engine via decrypted metadata

- [x] Save .encrypted + .json metadata, return pickup link

- [ ] Update PacMan like mini game logic revamp "(LOW PRIORITY)"

- [ ] Update PacMan like mini game base revamp "(LOW PRIORITY)"

---

##### /paccrypt_algos/ - Modular Crypto Engines

- [x] Create folder + interface

- [x] Remove basic cypher

Implement engines:

- [x] aes_gcm.py

- [x] aes_cbc.py

- [x] xchacha.py

- [x] rsa_hybrid.py

- [x] ~~PQCrypt_hybrid.py (Testing)~~ **REMOVED: Post-quantum crypto removed for simplicity**

- [x] Each must expose:

```
def encrypt_text(text, key): ...
def decrypt_text(ciphertext, key): ...
def encrypt_file(in_path, out_path, key): ...
def decrypt_file(in_path, out_path, key): ...
def generate_key_pair(): ... (for RSA hybrid)
```
**COMPLETED: All modules implemented with correct API**

---

### Phase 2: PacShare - Reimplementation

/encrypt Route Flow

- [x] JS submits (PacShare "Form"):
- [x] File
- [x] pickup_password (for metadata)
- [x] encryption_password (for file)
- [x] encryption_mode
- [x] 2FA TOTP setup (Yubi/Passkey not implemented)

- [x] Python logic:
- [x] Encrypt file using selected algo + encryption_password
- [x] Generate metadata dict:
- [x] filename, enc_mode, pickup_hash, timestamp, optional 2FA
- [x] Encrypt metadata using AES-GCM derived from pickup_password
- [x] Save .{algorithm}.encrypted and .json files
- [x] Generate random file_id
- [x] Return /pickup/<file_id> link

> [!IMPORTANT]
> Both passwords are required. One reveals the mode + metadata, the other decrypts the file.

---

##### /pickup/<file_id> Route Flow

- [x] Prompt for pickup_password

- [x] Decrypt .json metadata and validate hash

- [x] Show original filename, prompt for encryption_password

- [x] Load correct module, decrypt file

- [x] Offer file download

---

##### Metadata Structure (Encrypted JSON)

```
"filename": "report.pdf",
"algorithm": "aes_cbc",
"pickup_password": "<sha256>",
"created_at": "2025-08-05T18:00Z",
"require_2fa": true,  // optional
"totp_secret": "base32string",  // optional
"service_name": "PacCrypt File: report.pdf..."  // optional
```

> [!NOTE]
> Stored as .json
> Encrypted with AES-GCM using key derived from pickup_password
> **COMPLETED: Metadata encryption implemented**

---

### Phase 3: External API Access (/api/*)

##### Endpoint	Description

```
✅ GET /api/algorithms        List available encryption algorithms
✅ POST /api/generate-keypair Generate RSA key pairs  
✅ POST /api/encrypt          File/text encryption (returns encrypted data)
✅ POST /api/decrypt          File/text decryption  
✅ POST /api/pacshare         Upload + encrypt + return pickup link (JSON)
❌ POST /api/ps-pickup        Provide pickup ID + passwords, return decrypted file (Use web interface)
❌ GET /api/version           Return current version tag (Not implemented)
```

> [!NOTE]  
> **COMPLETED: Core API endpoints implemented**
> Pickup is handled via web interface at /pickup/<file_id>
> Encryption password is never saved server-side

---

### Phase 4: CLI Tool (Offline and API Hybrid)

- [ ] Create PacCrypt-CLI repo

- [ ] paccrypt-cli command

- [ ] Local encrypt/decrypt support

##### Support:

- [ ] --share-api to change api address (in case user is self hosting PacCrypt-Webapp)
- Default api from https://paccrypt.unnaturalll.dev/

- [ ] --share to upload via /api/ps-send

- [ ] --pickup <id> to download + decrypt via /api/ps-pickup

##### Always require (Send + Pickup)

- [ ] --method (to define encryption type)

- [ ] --pickup-password

- [ ] --encryption-password

Optional (Send + Pickup)

- [ ] 2FA Token
- No Yubi or passkey support for API calls

- [ ] --help (Shows command usage)

- [ ] CLI PacMan like mini game (LOW PRIORITY)

---

### Phase 5: Local GUI Applications

##### Linux (First)

- [ ] PyQt6 or GTK

- [ ] Same features as the Webapp

- [ ] Support for PacShare through API calls
- Default https://paccrypt.unnaturalll.dev/
- User changeable if the webapp is self hosted

- [ ] Text Encryption / Decryption mode

- [ ] Text Password

- [ ] Text input / output

- [ ] PacShare Mode selector

- [ ] PacShare File Uploader

- [ ] PacShare Pickup Password

- [ ] PacShare Encryption / Decryption password

- [ ] PacShare 2FA Token support
- No Yubi/Passkey support for API calls

- [ ] PacShare error message if devices is offline or server can't be reached

- [ ] KDE Dolphin context integration (right-click → encrypt | decrypt | share - share opens the paccrypt gui with the file already staged)

##### Android

- [ ] Kivy or BeeWare

- [ ] Same features as the Webapp

- [ ] Support for PacShare through API calls
- Default https://paccrypt.unnaturalll.dev/
- User changeable if the webapp is self hosted

- [ ] Text Encryption / Decryption mode

- [ ] Text Password

- [ ] Text input / output

- [ ] PS Mode selector

- [ ] PS File Uploader

- [ ] PS Pickup Password

- [ ] PS Encryption / Decryption password

- [ ] PS 2FA Token support
- No Yubi/Passkey support for API calls

- [ ] PS error message if devices is offline or server can't be reached

> [!IMPORTANT]
> No 	<ins>Windows</ins> support for a application, only webapp, and maybe CLI support.

`Linux master race`

---

### PacShare File Format ✅ **COMPLETED**

```
pacshare/
├── <file_id>.<algorithm>.encrypted     # Encrypted binary file  
└── <file_id>.json                      # Encrypted metadata (JSON)
```

**Current Implementation:**
- Files are stored as `.{algorithm}.encrypted` (e.g., `.aes_cbc.encrypted`)
- Metadata stored as `.json` files with encrypted content
- Algorithm info embedded in filename for automatic detection

---

### Development Order

0.	- [x] **Phase 0 Tasks** ✅
1.	- [x] **paccrypt_algos/ + aes_gcm.py** ✅
2.	- [x] **app.py routes: /encrypt, /pickup/<id>** ✅
3.	- [x] **Add /decrypt route** ✅
4.	- [x] **Build metadata encryption helpers** ✅
5.	- [x] **Finish other engine modules** ✅
6.	- [x] **Build /api/* equivalents** ✅
7.	- [x] **Update README.md with all changes to the webapp** ✅
8.	- [x] **Create a new installation guide** ✅ (Included in README.md)
9.	- [ ] Build CLI ⏳ *Next Priority*
10.	- [ ] Test CLI with --pickup + --share
12.	- [ ] Build GUI app on Linux
13.	- [ ] Test GUI app on Linux
14.	- [ ] Build GUI app on Android
15.	- [ ] Test GUI app on Android
16.	- [ ] Finalize all releases and push to main
17.	- [ ] Create Wiki

**🎉 WEBAPP CORE COMPLETE! 🎉**

**Current Status:** All core webapp functionality implemented including:
- ✅ Modular encryption engines (AES-GCM, AES-CBC, XChaCha20, RSA Hybrid)
- ✅ Complete API with documentation
- ✅ PacShare file sharing with 2FA support
- ✅ Admin panel with full management features
- ✅ Cross-platform deployment scripts
- ✅ Comprehensive documentation

---

### Current Webapp Structure ✅ **COMPLETED**

```
PacCrypt-Webapp/
├── app.py                          # Main Flask application ✅
├── README.md                       # Updated documentation ✅
├── ROADMAP.md                     # This file ✅
├── API.md                         # API documentation ✅ *NEW*
├── LICENSE                        # MIT License ✅
├── application_data/ ✅            # Application configuration
│   ├── control_scripts/ ✅         # Server management scripts
│   │   ├── start_dev.py ✅        # Development mode starter
│   │   ├── start_prod.py ✅       # Production mode starter
│   │   ├── restart_dev.py ✅      # Development restart
│   │   ├── restart_prod.py ✅     # Production restart
│   │   └── stop.py ✅             # Server stop script
│   ├── requirements.txt ✅        # Python dependencies
│   ├── settings.json ✅          # Application settings
│   ├── admin_creds.json ✅       # Encrypted admin credentials
│   ├── admin_key.key ✅         # Admin encryption key
│   └── admin_logs.enc ✅        # Encrypted audit logs
├── paccrypt_algos/ ✅              # Encryption modules
│   ├── __init__.py ✅             # Package initialization
│   ├── aes_cbc.py ✅             # AES-CBC implementation
│   ├── aes_gcm.py ✅             # AES-GCM implementation
│   ├── xchacha.py ✅             # XChaCha20-Poly1305
│   └── rsa_hybrid.py ✅          # RSA hybrid encryption
├── pacshare/ ✅                    # File upload storage
│   ├── *.{algorithm}.encrypted ✅  # Encrypted uploaded files
│   └── *.json ✅                  # File metadata
├── templates/ ✅                   # HTML templates
│   ├── index.html ✅              # Main interface
│   ├── pickup.html ✅             # File pickup page
│   ├── admin*.html ✅             # Admin panel pages
│   └── error pages (403,404,500) ✅
└── static/ ✅                     # Static assets
    ├── css/styles.css ✅          # Application styling
    ├── js/ ✅                     # JavaScript modules
    ├── img/ ✅                    # Images and icons
    ├── fonts/ ✅                  # Custom fonts
    └── audio/ ✅                  # Sound effects
```

**🏆 PROJECT STRUCTURE FULLY IMPLEMENTED 🏆**
