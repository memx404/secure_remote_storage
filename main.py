"""
Core encryption utility.

Day 2 Update: RSA Key Generation with organized storage.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_identity():
    """
    Generates a 2048-bit RSA key pair and saves them to a 'keys' directory.

    This establishes the cryptographic identity required for the 
    hybrid encryption scheme.
    """
    # Ensure the storage directory exists to prevent FileNotFoundError
    key_dir = "keys"
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    password = b"student_password_123"

    # Serialize Private Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    # Serialize Public Key (No password needed for public info)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save both files
    with open(os.path.join(key_dir, "private_key.pem"), "wb") as f:
        f.write(private_pem)

    with open(os.path.join(key_dir, "public_key.pem"), "wb") as f:
        f.write(public_pem)

    print(f"Identity created in '{key_dir}/' directory.")

if __name__ == "__main__":
    generate_identity()