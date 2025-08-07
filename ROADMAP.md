> [!IMPORTANT]
> Fully modular code for encryption libraries, ensure metadata is stored as encrypted hashs for PacShare, Revamp PacShares secure file send and pickup, and create a CLI and local application (Linux and Android).

---

### Phase 0

- [x] Remove docker files (Dropping official docker support)

- [x] Add roadmap.md to repo

- [x] Create /application_data/ folder (for server settings, admin login and creds)

- [x] Create scripts folder in /application_data/

- [x] Create /paccrypt_algos/ folder

- [ ] Builder better start, stop and restart scripts both prod and dev (Universal)

- [ ] Add a button in the admin panel to switch to and from prod and dev modes - **Saving for UI Revamp**

### Phase 1: app.py - Modular Python Web App

##### app.py Responsibilities

- [ ] Flask app + routing

- [ ] Handle:
- /encrypt
- /decrypt
- /pickup/<file_id>

- [ ] Receive:
- File or text
- pickup_password (required)
- encryption_password (required)
- encryption_mode

- [ ] Encrypt metadata using pickup password

- [ ] Encrypt file using encryption password

- [ ] Dynamically load correct engine via decrypted metadata

- [ ] Save .enc + .meta, return pickup link

- [ ] Update PacMan like mini game logic revamp "(LOW PRIORITY)"

- [ ] Update PacMan like mini game base revamp "(LOW PRIORITY)"

---

##### /paccrypt_algos/ - Modular Crypto Engines

- [ ] Create folder + interface

- [ ] Remove basic cypher

Implement engines:

- [ ] aes_gcm.py

- [ ] aes_cbc.py

- [ ] xchacha.py

- [ ] rsa_hybrid.py

- [ ] kyber_hybrid.py (Testing)

- [ ] Each must expose:

```
def encrypt\_text(text, key, metadata): ...
def decrypt\_text(ciphertext, key, metadata): ...
def encrypt\_file(in\_path, out\_path, key, metadata): ...
def decrypt\_file(in\_path, out\_path, key, metadata): ...
def get\_name(): return "AES-GCM"
```

---

### Phase 2: PacShare - Reimplementation

/encrypt Route Flow

- [ ] JS submits (PacShare "Form"):
- File
- pickup_password (for metadata)
- encryption_password (for file)
- encryption_mode
- 2FA token code / Yubi/Passkey set up

- [ ] Python logic:
- Encrypt file using selected algo + encryption_password
- Generate metadata dict:
- filename, enc_mode, pickup_hash, timestamp, optional 2FA
- Encrypt metadata using AES-GCM derived from pickup_password
- Save .paccrypt and .meta files
- Generate random file_id
- Return /pickup/<file_id> link

> [!IMPORTANT]
> Both passwords are required. One reveals the mode + metadata, the other decrypts the file.

---

##### /pickup/<file_id> Route Flow

- [ ] Prompt for pickup_password

- [ ] Decrypt .meta and validate hash

- [ ] Show original filename, prompt for encryption_password

- [ ] Load correct module, decrypt file

- [ ] Offer file download

---

##### Metadata Structure (Encrypted JSON)

```
"filename": "report.pdf",
"enc\_mode": "aes\_gcm",
"pickup\_hash": "<argon2>",
"created\_at": "2025-08-05T18:00Z",
"2fa\_seed": "base32string",  // optional
"yubi\_token\_hash": "sha256", // optional
```

> [!NOTE]
> Stored as .meta
> Encrypted with AES-GCM using key from pickup\_password

---

### Phase 3: External API Access (/api/*)

##### Endpoint	Description

```
POST /api/encrypt	Local-only file/text encryption (returns file/meta)
POST /api/ps-send	Upload + encrypt + return pickup link (JSON)
POST /api/ps-pickup	Provide pickup ID + passwords, return decrypted file
POST /api/decrypt	Decrypt local .enc + .meta bundle
GET /api/version	Return current version tag
```

> [!NOTE]
> These endpoints must receive both passwords. Encryption password is never saved.

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

### PacShare File Format

```
pacshare/
├── <file_id>pdf/jpeg/etc.paccrypt      # Encrypted binary file
└── <file_id>meta.paccrypt		# Encrypted metadata
```

---

### Development Order

0.	- [ ] Phase 0 Tasks
1.	- [ ] paccrypt_algos/ + aes_gcm.py
2.	- [ ] app.py routes: /encrypt, /pickup/<id>
3.	- [ ] Add /decrypt route
4.	- [ ] Build metadata encryption helpers
5.	- [ ] Finish other engine modules
6.	- [ ] Build /api/* equivalents
7.	- [ ] Update README.md with all changed to the webapp.
8.	- [ ] Create a new installation guide.
9.	- [ ] Build CLI
10.	- [ ] Test CLI with --pickup + --share
12.	- [ ] Build GUI app on Linux
13.	- [ ] Test GUI app on Linux
14.	- [ ] Build GUI app on Android
15.	- [ ] Test GUI app on Android
16.	- [ ] Finilize all releases and push to main.
17.	- [ ] Create Wiki

---

### Draft tree for webapp

```
paccrypt-webapp/
├── static/
│   ├── audio/
│   │   └── chomp.mp3
│   ├── css/
│   │   └── styles.css
│   ├── fonts/
│   │   └── PressStart2P-Regular.ttf
│   ├── img/
│   │   ├── Github_logo.png
│   │   ├── PacCrypt.png
│   │   ├── PacCrypt_W-Background.png
│   │   ├── PacCrypt_W-Backgroud_Name.png
│   │   ├── PacCrypt_W-Name.png
│   │   └── sitemap.png <-- **Change img**
│   └── js/ <-- **Pending changes**
│       ├── encryption.js
│       ├── fileops.js
│       ├── main.js
│       ├── pacman.js
│       └── ui.js
├── templates/
│   ├── 403.html
│   ├── 404.html
│   ├── 500.html
│   ├── admin.html
│   ├── admin_login.html
│   ├── admin_settings.html
│   ├── admin_setup.html
│   ├── index.html
│   └── pickup.html
├── application_data/ <-- *New*
│   ├── scripts/ <-- *New*
│   │   ├── start_dev <-- *Moved*
│   │   ├── start_prod <-- *Moved*
│   │   ├── restart_dev <-- *New*
│   │   ├── restart_prod <-- *New*
│   │   └── stop <-- *New*
│   ├── settings.json <-- *Moved*
│   ├── requirements.txt <-- *Moved*
│   ├── admin_cred <-- **Generated once admin is setup** / *Moved*
│   └── admin_hash <-- **Generated once admin is setup** / *Moved*
├── paccrypt_algos/ <-- *New*
│   ├── aes_gcm.py <-- *New*
│   ├── aes_cbc.py <-- *New*
│   ├── xchacha.py <-- *New*
│   ├── rsa_hybrid.py <-- *New*
│   └── kyber_hybrid.py <-- *New*
├── pacshare/ <-- **Generated at time of first PacShare upload, location customizable** / *New*
│   ├── <file_id>pdf/jpeg/etc.paccrypt <-- **Encrypted binary file** / *Moved*
│   └── <file_id>meta.paccrypt <-- **Encrypted metadata** / *Moved*
├── README.md <-- **Needs Updated**
├── ROADMAP.md
├── LICENSE <-- *New*
└── app.py
```
