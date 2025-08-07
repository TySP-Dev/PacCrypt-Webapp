import os
import base64
import json
import importlib
import sys
from pathlib import Path
from typing import Optional

from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt as kem_encapsulate, decrypt as kem_decapsulate

# === Allow Hybrid Selector ===
PARENT_DIR = Path(__file__).resolve().parent.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.append(str(PARENT_DIR))

# === Constants ===
KEM_ALG = "ML-KEM-768"
AES_KEY_SIZE = 32  # 256-bit
SYMMETRIC_DEFAULT = "aes_gcm"

# === Base64 Helpers ===
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))

# === Dynamic Engine Loader ===
def load_engine(engine_name: str):
    try:
        return importlib.import_module(f'paccrypt_algos.{engine_name}')
    except ModuleNotFoundError:
        raise ValueError(f"Encryption engine '{engine_name}' not found.")

# === Encrypt Text ===
def encrypt_text(plaintext: str, public_key: bytes, engine_name: str = SYMMETRIC_DEFAULT) -> str:
    engine = load_engine(engine_name)
    kem_ciphertext, shared_secret = kem_encapsulate(public_key)
    aes_key = shared_secret[:AES_KEY_SIZE]

    encrypted_data = engine.encrypt_text(plaintext, aes_key.hex())
    header = json.dumps({"alg": engine_name}).encode()
    payload = len(kem_ciphertext).to_bytes(2, 'big') + kem_ciphertext + header + b'\0' + encrypted_data.encode()
    return b64encode(payload)

# === Decrypt Text ===
def decrypt_text(encrypted_b64: str, private_key: bytes) -> str:
    raw = b64decode(encrypted_b64)
    kem_len = int.from_bytes(raw[:2], 'big')
    kem_ct = raw[2:2 + kem_len]
    rest = raw[2 + kem_len:]
    header_data, encrypted_data = rest.split(b'\0', 1)
    engine_name = json.loads(header_data.decode()).get("alg")

    shared_secret = kem_decapsulate(private_key, kem_ct)
    aes_key = shared_secret[:AES_KEY_SIZE]

    engine = load_engine(engine_name)
    return engine.decrypt_text(encrypted_data.decode(), aes_key.hex())

# === Encrypt File ===
def encrypt_file(in_path: str, out_path: str, public_key: bytes, engine_name: str = SYMMETRIC_DEFAULT):
    engine = load_engine(engine_name)
    kem_ciphertext, shared_secret = kem_encapsulate(public_key)
    aes_key = shared_secret[:AES_KEY_SIZE]

    with open(in_path, 'rb') as f:
        plaintext = f.read()

    encrypted = engine.encrypt_file_bytes(plaintext, aes_key.hex())
    header = json.dumps({"alg": engine_name}).encode()
    payload = len(kem_ciphertext).to_bytes(2, 'big') + kem_ciphertext + header + b'\0' + encrypted

    with open(out_path, 'wb') as f:
        f.write(payload)

# === Decrypt File ===
def decrypt_file(in_path: str, out_path: str, private_key: bytes):
    with open(in_path, 'rb') as f:
        raw = f.read()

    kem_len = int.from_bytes(raw[:2], 'big')
    kem_ct = raw[2:2 + kem_len]
    rest = raw[2 + kem_len:]
    header_data, encrypted_data = rest.split(b'\0', 1)
    engine_name = json.loads(header_data.decode()).get("alg")

    shared_secret = kem_decapsulate(private_key, kem_ct)
    aes_key = shared_secret[:AES_KEY_SIZE]

    engine = load_engine(engine_name)
    plaintext = engine.decrypt_file_bytes(encrypted_data, aes_key.hex())

    with open(out_path, 'wb') as f:
        f.write(plaintext)

# === Engine Name ===
def get_name():
    return "PQCrypto Hybrid"
