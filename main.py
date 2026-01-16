"""
Core encryption script.

Implements AES symmetric encryption using the Fernet standard.
"""

from cryptography.fernet import Fernet

key = Fernet.generate_key()

def encrypt_file(filename):
    """
    Reads a file from disk and encrypts its content.
    """
    cipher = Fernet(key)

    # Opening in standard read mode
    with open(filename, "r") as f:
        file_data = f.read()

    encrypted_data = cipher.encrypt(file_data.encode())

    # Save the encrypted output
    with open(filename + ".enc", "w") as f:
        f.write(encrypted_data.decode())

if __name__ == "__main__":
    # Create a dummy file to test
    with open("test.txt", "w") as f:
        f.write("Confidential Data")

    encrypt_file("test.txt")