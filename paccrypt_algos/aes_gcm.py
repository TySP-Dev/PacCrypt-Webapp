import os
import base64
import json
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# === Constants ===
SALT_LENGTH = 16
IV_LENGTH = 12
PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32  # 256 bits

# === Base64 Helpers ===
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))

# === Key Derivation ===
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

# === Encrypt Text ===
def encrypt_text(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)

    payload = salt + iv + ciphertext
    return b64encode(payload)

# === Decrypt Text ===
def decrypt_text(encrypted_b64: str, password: str) -> str:
    raw = b64decode(encrypted_b64)
    salt = raw[:SALT_LENGTH]
    iv = raw[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = raw[SALT_LENGTH + IV_LENGTH:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode('utf-8')

# === Metadata-less file interface (optional placeholders) ===
def encrypt_file(in_path, out_path, key, metadata: Optional[dict] = None):
    raise NotImplementedError("File encryption not implemented yet.")

def decrypt_file(in_path, out_path, key, metadata: Optional[dict] = None):
    raise NotImplementedError("File decryption not implemented yet.")

# === Engine Name ===
def get_name():
    return "AES-GCM"
