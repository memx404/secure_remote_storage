"""
Core encryption utility.

Day 2 Update: Adding RSA Key Generation to establish user identity.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_identity():
    """
    Generates a 2048-bit RSA key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # FIXED: Encrypting the private key with a hardcoded password
    # hardcoded password for locking the private key
    password = b"l0cker1212"

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # Used BestAvailableEncryption to lock the file
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    with open("private_key.pem", "wb") as f:
        f.write(pem)

    print("Identity generated securely.")

if __name__ == "__main__":
    generate_identity()