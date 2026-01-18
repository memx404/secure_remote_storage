"""
Core encryption utility.

Day 2 Update: Adding RSA Key Generation to establish user identity.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_identity():
    """
    Generates a 2048-bit RSA key pair.

    The private key is the user's secret identity.
    The public key will be used by others to encrypt data for this user.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("private_key.pem", "wb") as f:
        f.write(pem)

    print("Identity generated. Private key saved to 'private_key.pem'.")

if __name__ == "__main__":
    generate_identity()