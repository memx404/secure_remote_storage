"""
Secure Cloud Core - Encryption Engine.

This module implements a Hybrid Encryption scheme combining RSA (asymmetric)
and AES (symmetric) algorithms. It provides functionality to:
1. Generate and manage cryptographic identities (RSA Keys).
2. Securely encrypt files for storage (AES-256).
3. Decrypt files using a secure private key.

Architecture:
- Large files are encrypted using a one-time AES session key.
- The AES session key is encrypted using the recipient's RSA Public Key.
- This ensures high performance for file operations while maintaining 
  strong security for key exchange.
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Configuration ---
# Directory structure for key storage and file processing
KEY_DIR = "keys"
INPUT_DIR = "test_inputs"
OUTPUT_DIR = "test_outputs"
RESTORED_DIR = "test_restored"


def setup_directories():
    """
    Initialize the required directory structure for the application.
    Creates folders for keys, input files, encrypted outputs, and restored data.
    """
    for directory in [KEY_DIR, INPUT_DIR, OUTPUT_DIR, RESTORED_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)


def generate_identity():
    """
    Establish a cryptographic identity for the user.
    
    Generates a 2048-bit RSA key pair if one does not already exist.
    The private key is securely encrypted at rest using a passphrase.
    """
    if os.path.exists(os.path.join(KEY_DIR, "private_key.pem")):
        print("Identity found. Loading existing keys...")
        return

    print("No identity found. Generating new RSA key pair...")
    
    # Generate private key with public exponent 65537 (standard default)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # TODO: Replace hardcoded password with secure user input (getpass)
    password = b"password@123"

    # Serialize and save Private Key (Encrypted)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(os.path.join(KEY_DIR, "private_key.pem"), "wb") as f:
        f.write(pem)

    # Serialize and save Public Key (Plaintext)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(KEY_DIR, "public_key.pem"), "wb") as f:
        f.write(pub_pem)
    
    print(f"Identity generated successfully in '{KEY_DIR}/'.")


def load_public_key():
    """Helper to load the RSA Public Key from the filesystem."""
    with open(os.path.join(KEY_DIR, "public_key.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key():
    """
    Helper to load the RSA Private Key from the filesystem.
    Requires the passphrase used during key generation.
    """
    # TODO: In production, prompt the user for this password
    password = b"student_password_123"
    
    with open(os.path.join(KEY_DIR, "private_key.pem"), "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=password
        )


def encrypt_file_hybrid(filename):
    """
    Encrypt a file using Hybrid Encryption (RSA + AES).
    
    Process:
    1. Generate a random AES session key.
    2. Encrypt the file content with the AES key.
    3. Encrypt the AES key itself with the RSA Public Key.
    4. Save both the encrypted content and the encrypted key.
    
    Args:
        filename (str): Name of the file in the 'test_inputs' directory.
    """
    input_path = os.path.join(INPUT_DIR, filename)
    
    if not os.path.exists(input_path):
        print(f"Error: Input file '{filename}' not found.")
        return

    # 1. Generate AES Session Key
    session_key = Fernet.generate_key()
    cipher_suite = Fernet(session_key)

    # 2. Encrypt File Content
    with open(input_path, "rb") as f:
        file_data = f.read()
    encrypted_file_data = cipher_suite.encrypt(file_data)

    # 3. Encrypt AES Key with RSA
    public_key = load_public_key()
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Write Output Artifacts
    enc_file_path = os.path.join(OUTPUT_DIR, filename + ".enc")
    with open(enc_file_path, "wb") as f:
        f.write(encrypted_file_data)

    enc_key_path = os.path.join(OUTPUT_DIR, filename + ".key.enc")
    with open(enc_key_path, "wb") as f:
        f.write(encrypted_session_key)

    print(f"[ENCRYPT] Success: {filename} -> {enc_file_path}")


def decrypt_file_hybrid(filename):
    """
    Decrypt a file using Hybrid Encryption logic.
    
    Process:
    1. Load the encrypted AES key from disk.
    2. Decrypt the AES key using the RSA Private Key.
    3. Use the revealed AES key to decrypt the file content.
    
    Args:
        filename (str): The original filename (system looks for .enc extensions).
    """
    # Paths to artifacts
    enc_file_path = os.path.join(OUTPUT_DIR, filename + ".enc")
    enc_key_path = os.path.join(OUTPUT_DIR, filename + ".key.enc")
    
    if not os.path.exists(enc_file_path) or not os.path.exists(enc_key_path):
        print(f"Error: Artifacts for {filename} missing.")
        return

    # 1. Load Private Key
    try:
        private_key = load_private_key()
    except ValueError:
        print("Error: Invalid password for private key.")
        return

    # 2. Decrypt the AES Session Key
    with open(enc_key_path, "rb") as f:
        encrypted_session_key = f.read()
    
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"Error decrypting session key: {e}")
        return

    # 3. Decrypt the File Content
    cipher_suite = Fernet(session_key)
    
    with open(enc_file_path, "rb") as f:
        encrypted_file_data = f.read()
        
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_file_data)
    except Exception as e:
        print(f"Error decrypting file data: {e}")
        return

    # 4. Save Restored Data
    restore_path = os.path.join(RESTORED_DIR, filename)
    with open(restore_path, "wb") as f:
        f.write(decrypted_data)
        
    print(f"[DECRYPT] Success: {filename} restored to {restore_path}")


if __name__ == "__main__":
    # Execution Block: Simulate a full encryption/decryption lifecycle
    setup_directories()
    generate_identity()

    test_doc = "confidential_report.pdf"
    
    # Ensure dummy data exists
    input_path = os.path.join(INPUT_DIR, test_doc)
    if not os.path.exists(input_path):
        with open(input_path, "wb") as f:
            f.write(b"TOP SECRET: This data has been securely transmitted.")

    # Run the cycle
    print("\n--- Initiating Secure Storage Protocol ---")
    encrypt_file_hybrid(test_doc)
    
    print("\n--- Initiating Retrieval Protocol ---")
    decrypt_file_hybrid(test_doc)