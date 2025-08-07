import os
import sys

from aes_gcm import encrypt_text as aesgcm_encrypt_text, decrypt_text as aesgcm_decrypt_text, \
                    encrypt_file as aesgcm_encrypt_file, decrypt_file as aesgcm_decrypt_file
from aes_cbc import encrypt_text as aescbc_encrypt_text, decrypt_text as aescbc_decrypt_text, \
                    encrypt_file as aescbc_encrypt_file, decrypt_file as aescbc_decrypt_file
from xchacha import encrypt_text as xchacha_encrypt_text, decrypt_text as xchacha_decrypt_text, \
                    encrypt_file as xchacha_encrypt_file, decrypt_file as xchacha_decrypt_file
import rsa_hybrid
import pqcrypto_hybrid

def load_text(path, binary=False):
    with open(path, 'rb' if binary else 'r') as f:
        return f.read()

def save_text(path, data, binary=False):
    with open(path, 'wb' if binary else 'w') as f:
        f.write(data)

def select_symmetric():
    print("\n🔀 Select symmetric engine:")
    choices = ["aes_gcm", "aes_cbc", "xchacha"]
    for i, c in enumerate(choices):
        print(f"  [{i}] {c}")
    while True:
        try:
            choice = int(input("Choice: "))
            return choices[choice]
        except (ValueError, IndexError):
            print("❌ Invalid choice. Try again.")

def hybrid_cli(name, module, key_ext, symmetric_engine, is_pem=False):
    while True:
        print(f"\n=== PacCrypt {name} Debug Mode ({symmetric_engine.upper()}) ===")
        print("Choose:")
        print("  [g] Generate keypair")
        print("  [e] Encrypt text")
        print("  [d] Decrypt text")
        print("  [ef] Encrypt file")
        print("  [df] Decrypt file")
        print("  [b] Back to engine menu")
        print("  [q] Quit script")

        mode = input("\nMode (g/e/d/ef/df/b/q): ").strip().lower()

        if mode == 'q':
            return 'quit'
        elif mode == 'b':
            return 'back'

        try:
            if mode == 'g':
                priv, pub = module.generate_key_pair() if hasattr(module, 'generate_key_pair') else module.generate_keypair()
                save_text(f"{name}_public.{key_ext}", pub, binary=True)
                save_text(f"{name}_private.{key_ext}", priv, binary=True)
                print(f"✅ Keypair saved to {name}_public.{key_ext} / {name}_private.{key_ext}")

            elif mode == 'e':
                plaintext = input("Text to encrypt: ")
                pub_path = input("Public key path: ").strip()
                pub = load_text(pub_path, binary=not is_pem)
                result = module.encrypt_text(plaintext, pub, symmetric_engine)
                print(f"\n🔐 Encrypted Base64:\n{result}")

            elif mode == 'd':
                encrypted = input("Encrypted Base64 input: ")
                priv_path = input("Private key path: ").strip()
                priv = load_text(priv_path, binary=not is_pem)
                result = module.decrypt_text(encrypted, priv)
                print(f"\n📝 Decrypted:\n{result}")

            elif mode == 'ef':
                in_path = input("Input file path: ").strip()
                out_path = in_path + ".paccrypt"
                pub_path = input("Public key path: ").strip()
                pub = load_text(pub_path, binary=not is_pem)
                module.encrypt_file(in_path, out_path, pub, symmetric_engine)
                print(f"✅ File encrypted and saved to: {out_path}")

            elif mode == 'df':
                in_path = input("Encrypted file path: ").strip()
                out_path = in_path.replace(".paccrypt", "")
                priv_path = input("Private key path: ").strip()
                priv = load_text(priv_path, binary=not is_pem)
                module.decrypt_file(in_path, out_path, priv)
                print(f"✅ File decrypted and saved to: {out_path}")
            else:
                print("❌ Invalid option.")
        except Exception as e:
            print(f"❌ Error: {e}")

def simple_cli(name, encrypt_text, decrypt_text, encrypt_file, decrypt_file):
    while True:
        print(f"\n=== PacCrypt {name} Debug Mode ===")
        print("Choose:")
        print("  [e] Encrypt text")
        print("  [d] Decrypt text")
        print("  [ef] Encrypt file")
        print("  [df] Decrypt file")
        print("  [b] Back to engine menu")
        print("  [q] Quit script")

        mode = input("\nMode (e/d/ef/df/b/q): ").strip().lower()

        if mode == 'q':
            return 'quit'
        elif mode == 'b':
            return 'back'

        try:
            if mode == 'e':
                plaintext = input("Plaintext to encrypt: ")
                password = input("Password: ")
                result = encrypt_text(plaintext, password)
                print(f"\n🔐 Encrypted Base64:\n{result}")

            elif mode == 'd':
                encrypted = input("Encrypted Base64 input: ")
                password = input("Password: ")
                result = decrypt_text(encrypted, password)
                print(f"\n📝 Decrypted:\n{result}")

            elif mode == 'ef':
                in_path = input("Input file path: ").strip()
                out_path = in_path + ".paccrypt"
                password = input("Password: ")
                encrypt_file(in_path, out_path, password)
                print(f"✅ File encrypted and saved to: {out_path}")

            elif mode == 'df':
                in_path = input("Encrypted file path: ").strip()
                out_path = in_path.replace(".paccrypt", "")
                password = input("Password: ")
                decrypt_file(in_path, out_path, password)
                print(f"✅ File decrypted and saved to: {out_path}")
            else:
                print("❌ Invalid option.")
        except Exception as e:
            print(f"❌ Error: {e}")


# === PacCrypt CLI Entry ===
while True:
    print("\n=== PacCrypt Hardcoded CLI ===")
    print("Pick an engine:")
    print("  [0] AES-GCM")
    print("  [1] AES-CBC")
    print("  [2] XChaCha20-Poly1305")
    print("  [3] RSA Hybrid (with selectable symmetric)")
    print("  [4] PQCrypto Hybrid (with selectable symmetric)")
    print("  [q] Quit")

    choice = input("Choice: ").strip().lower()
    if choice == 'q':
        print("👋 Bye.")
        sys.exit(0)

    symmetric_engine = None
    if choice in ['3', '4']:
        symmetric_engine = select_symmetric()

    engines = {
        '0': lambda: simple_cli("AES-GCM", aesgcm_encrypt_text, aesgcm_decrypt_text, aesgcm_encrypt_file, aesgcm_decrypt_file),
        '1': lambda: simple_cli("AES-CBC", aescbc_encrypt_text, aescbc_decrypt_text, aescbc_encrypt_file, aescbc_decrypt_file),
        '2': lambda: simple_cli("XChaCha20-Poly1305", xchacha_encrypt_text, xchacha_decrypt_text, xchacha_encrypt_file, xchacha_decrypt_file),
        '3': lambda: hybrid_cli("RSA_Hybrid", rsa_hybrid, "pem", symmetric_engine, is_pem=True),
        '4': lambda: hybrid_cli("PQCrypto_Hybrid", pqcrypto_hybrid, "bin", symmetric_engine),
    }

    if choice in engines:
        result = engines[choice]()
        if result == 'quit':
            print("👋 Quitting.")
            sys.exit(0)
        # If 'back', just loops again to show engine menu
    else:
        print("❌ Invalid choice.")
