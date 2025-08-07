import os
import base64
import json
import importlib
from typing import Optional, Tuple
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

PARENT_DIR = Path(__file__).resolve().parent.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.append(str(PARENT_DIR))

# === Constants ===
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32  # 256-bit

# === Base64 Helpers ===
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))

# === RSA Key Generation ===
def generate_key_pair() -> Tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# === Dynamic Engine Loader ===
def load_engine(engine_name: str):
    try:
        return importlib.import_module(f'paccrypt_algos.{engine_name}')
    except ModuleNotFoundError:
        raise ValueError(f"Encryption engine '{engine_name}' not found.")

# === Encrypt Text ===
def encrypt_text(plaintext: str, public_key_pem: str, engine_name: str = "aes_gcm") -> str:
    engine = load_engine(engine_name)
    aes_key = os.urandom(AES_KEY_SIZE)

    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_data = engine.encrypt_text(plaintext, aes_key.hex())
    header = json.dumps({"alg": engine_name}).encode()
    payload = len(encrypted_key).to_bytes(2, 'big') + encrypted_key + header + b'\0' + encrypted_data.encode()
    return b64encode(payload)

# === Decrypt Text ===
def decrypt_text(encrypted_b64: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    raw = b64decode(encrypted_b64)

    enc_key_len = int.from_bytes(raw[:2], 'big')
    enc_key = raw[2:2 + enc_key_len]
    rest = raw[2 + enc_key_len:]
    header_data, encrypted_data = rest.split(b'\0', 1)
    engine_name = json.loads(header_data.decode()).get("alg")

    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    engine = load_engine(engine_name)
    return engine.decrypt_text(encrypted_data.decode(), aes_key.hex())

# === Encrypt File ===
def encrypt_file(in_path: str, out_path: str, public_key_pem: str, engine_name: str = "aes_gcm"):
    engine = load_engine(engine_name)
    aes_key = os.urandom(AES_KEY_SIZE)

    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(in_path, 'rb') as f:
        plaintext = f.read()

    encrypted_data = engine.encrypt_file_bytes(plaintext, aes_key.hex())
    header = json.dumps({"alg": engine_name}).encode()
    payload = len(encrypted_key).to_bytes(2, 'big') + encrypted_key + header + b'\0' + encrypted_data

    with open(out_path, 'wb') as f:
        f.write(payload)

# === Decrypt File ===
def decrypt_file(in_path: str, out_path: str, private_key_pem: str):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())

    with open(in_path, 'rb') as f:
        raw = f.read()

    enc_key_len = int.from_bytes(raw[:2], 'big')
    enc_key = raw[2:2 + enc_key_len]
    rest = raw[2 + enc_key_len:]
    header_data, encrypted_data = rest.split(b'\0', 1)
    engine_name = json.loads(header_data.decode()).get("alg")

    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    engine = load_engine(engine_name)
    plaintext = engine.decrypt_file_bytes(encrypted_data, aes_key.hex())

    with open(out_path, 'wb') as f:
        f.write(plaintext)

# === Engine Name ===
def get_name():
    return "RSA Hybrid"
