"""
Core encryption script.

Implements AES symmetric encryption using the Fernet standard.
"""

from cryptography.fernet import Fernet

# Generate a random 32-byte key for the session
key = Fernet.generate_key()

def encrypt_data(data):
    """
    Encrypt a raw string using the session key.
    """
    cipher = Fernet(key)
    # Fernet operates on bytes, so we encode the string
    return cipher.encrypt(data.encode())

if __name__ == "__main__":
    print(f"Session Key: {key}")
    print(encrypt_data("Secret Message"))