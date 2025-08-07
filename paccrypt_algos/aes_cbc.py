import os
import base64
from typing import Optional

from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# === Constants ===
SALT_LENGTH = 16
IV_LENGTH = 16
PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32
HMAC_KEY_LENGTH = 32  # For HMAC-SHA256
HMAC_LENGTH = 32      # Output size of SHA256

# === Base64 Helpers ===
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))

# === Key Derivation ===
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH + HMAC_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    full_key = kdf.derive(password.encode('utf-8'))
    return full_key[:KEY_LENGTH], full_key[KEY_LENGTH:]

# === Encrypt Text ===
def encrypt_text(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    aes_key, hmac_key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    payload = salt + iv + ciphertext

    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(payload)
    mac = h.finalize()

    return b64encode(payload + mac)

# === Decrypt Text ===
def decrypt_text(encrypted_b64: str, password: str) -> str:
    raw = b64decode(encrypted_b64)

    salt = raw[:SALT_LENGTH]
    iv = raw[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = raw[SALT_LENGTH + IV_LENGTH:-HMAC_LENGTH]
    mac = raw[-HMAC_LENGTH:]

    aes_key, hmac_key = derive_key(password, salt)

    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(raw[:-HMAC_LENGTH])
    h.verify(mac)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode('utf-8')

# === Encrypt File ===
def encrypt_file(in_path, out_path, password: str, metadata: Optional[dict] = None):
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    aes_key, hmac_key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    payload = salt + iv + ciphertext

    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(payload)
    mac = h.finalize()

    with open(out_path, 'wb') as f:
        f.write(payload + mac)

# === Decrypt File ===
def decrypt_file(in_path, out_path, password: str, metadata: Optional[dict] = None):
    with open(in_path, 'rb') as f:
        raw = f.read()

    salt = raw[:SALT_LENGTH]
    iv = raw[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
    ciphertext = raw[SALT_LENGTH + IV_LENGTH:-HMAC_LENGTH]
    mac = raw[-HMAC_LENGTH:]

    aes_key, hmac_key = derive_key(password, salt)

    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(raw[:-HMAC_LENGTH])
    h.verify(mac)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    with open(out_path, 'wb') as f:
        f.write(plaintext)

# === Algo Name ===
def get_name():
    return "AES-CBC"
