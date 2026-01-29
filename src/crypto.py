"""
Cryptographic Engine Module.

Implements Hybrid Encryption (AES-256 + RSA-2048) logic.
Combines the speed of symmetric encryption with the security of asymmetric key exchange.
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encrypt_file(filename, input_dir, output_dir, public_key):
    
    input_path = os.path.join(input_dir, filename)
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file {filename} not found.")

    # 1. Generate a random AES Session Key (Symmetric)
    # This key is used to encrypt the actual file data quickly.
    session_key = Fernet.generate_key()
    cipher = Fernet(session_key)

    with open(input_path, "rb") as f:
        data = f.read()

    # Encrypt the file content with AES
    encrypted_data = cipher.encrypt(data)

    # 2. Encrypt the Session Key with the RSA Public Key (Asymmetric)
    # We use OAEP padding with SHA256 for maximum security.
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Save Artifacts
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Save the encrypted data
    with open(os.path.join(output_dir, filename + ".enc"), "wb") as f:
        f.write(encrypted_data)

    # Save the encrypted key so we can decrypt later
    with open(os.path.join(output_dir, filename + ".key.enc"), "wb") as f:
        f.write(encrypted_key)

    return True


def decrypt_file(filename, output_dir, restored_dir, private_key):
    enc_file = os.path.join(output_dir, filename + ".enc")
    enc_key = os.path.join(output_dir, filename + ".key.enc")

    if not os.path.exists(enc_file) or not os.path.exists(enc_key):
        raise FileNotFoundError("Encrypted artifacts missing.")

    # 1. Unlock the Session Key
    with open(enc_key, "rb") as f:
        encrypted_session_key = f.read()

    # Use RSA Private Key to decrypt the AES session key
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Decrypt the File Data
    cipher = Fernet(session_key)
    with open(enc_file, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    # 3. Save the Restored File
    if not os.path.exists(restored_dir):
        os.makedirs(restored_dir)

    with open(os.path.join(restored_dir, filename), "wb") as f:
        f.write(decrypted_data)

    return True
