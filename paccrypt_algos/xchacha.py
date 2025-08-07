import os
import base64
from typing import Optional
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# === Constants ===
SALT_LENGTH = 16
NONCE_LENGTH = 24
KEY_LENGTH = 32
PBKDF2_ITERATIONS = 200_000
TAG_LENGTH = 16

# === Base64 Helpers ===
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'))

# === Key Derivation ===
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

# === Encrypt Text ===
def encrypt_text(plaintext: str, password: str) -> str:
    salt = get_random_bytes(SALT_LENGTH)
    nonce = get_random_bytes(NONCE_LENGTH)
    key = derive_key(password, salt)

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    final = salt + nonce + ciphertext + tag
    return b64encode(final)

# === Decrypt Text ===
def decrypt_text(encrypted_b64: str, password: str) -> str:
    raw = b64decode(encrypted_b64)
    salt = raw[:SALT_LENGTH]
    nonce = raw[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    tag = raw[-TAG_LENGTH:]
    ciphertext = raw[SALT_LENGTH + NONCE_LENGTH:-TAG_LENGTH]

    key = derive_key(password, salt)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode('utf-8')

# === Encrypt File ===
def encrypt_file(in_path, out_path, password: str, metadata: Optional[dict] = None):
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_LENGTH)
    nonce = get_random_bytes(NONCE_LENGTH)
    key = derive_key(password, salt)

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(out_path, 'wb') as f:
        f.write(salt + nonce + ciphertext + tag)

# === Decrypt File ===
def decrypt_file(in_path, out_path, password: str, metadata: Optional[dict] = None):
    with open(in_path, 'rb') as f:
        raw = f.read()

    salt = raw[:SALT_LENGTH]
    nonce = raw[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    tag = raw[-TAG_LENGTH:]
    ciphertext = raw[SALT_LENGTH + NONCE_LENGTH:-TAG_LENGTH]

    key = derive_key(password, salt)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    with open(out_path, 'wb') as f:
        f.write(plaintext)

# === Engine Name ===
def get_name():
    return "XChaCha20-Poly1305"


if __name__ == "__main__":
    from Crypto.Cipher.ChaCha20_Poly1305 import ChaCha20Poly1305Cipher as _test  # Force import to validate availability
    from cryptography.exceptions import InvalidTag  # Still catchable for consistency
