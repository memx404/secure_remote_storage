"""
Key Management Module.

Handles the generation, storage, and retrieval of RSA cryptographic identities.
Ensures that private keys are always stored in an encrypted format.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_key_pair(key_dir="keys", password=b"student_password_123"):

    # Create keys folder to save public and private keys
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)

    private_path = os.path.join(key_dir, "private_key.pem")
    public_path = os.path.join(key_dir, "public_key.pem")

    # Check if keys already exist to avoid overwriting the user's identity
    if os.path.exists(private_path):
        print(f"Identity already exists in {key_dir}")
        return

    # Generate a 2048-bit RSA private key
    # public_exponent=65537 is the industry standard (F4)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Encrypt the private key using BestAvailableEncryption
    # This ensures the key is useless if stolen without the password
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    # Save Private Key
    with open(private_path, "wb") as f:
        f.write(pem)

    # Save Public Key (No encryption needed for public data)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, "wb") as f:
        f.write(pub_pem)

    print(f"New identity generated in {key_dir}")


def load_private_key(key_dir="keys", password=b"student_password_123"):
    # Load the encrypted Private Key from disk
    path = os.path.join(key_dir, "private_key.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def load_public_key(key_dir="keys"):
    # Load the Public Key from disk
    path = os.path.join(key_dir, "public_key.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
