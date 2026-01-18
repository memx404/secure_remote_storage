"""
Core encryption utility.

Day 2 Update: Implementing Hybrid Encryption.
We use RSA (Asymmetric) to secure the keys, and AES (Symmetric) to secure
the actual file data. This is the industry standard for secure cloud storage.
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Configuration for file paths
KEY_DIR = "keys"
INPUT_DIR = "test_inputs"
OUTPUT_DIR = "test_outputs"


def setup_directories():
    """Ensure all necessary test directories exist."""
    for directory in [KEY_DIR, INPUT_DIR, OUTPUT_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)


def generate_identity():
    """
    Generates a 2048-bit RSA key pair for the user.
    
    The private key is encrypted with a password before saving.
    The public key is saved in plain text.
    """
    if os.path.exists(os.path.join(KEY_DIR, "private_key.pem")):
        print("Identity already exists. Skipping generation.")
        return

    print("Generating new RSA Identity...")
    private_key = os.urandom(2048) # Just simulation logic for print, real logic below
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Password to lock the private key (Simulated user input)
    password = b"student_password_123"

    # Save Private Key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(os.path.join(KEY_DIR, "private_key.pem"), "wb") as f:
        f.write(pem)

    # Save Public Key
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(KEY_DIR, "public_key.pem"), "wb") as f:
        f.write(pub_pem)
    
    print(f"Keys saved to '{KEY_DIR}/'.")


def load_public_key():
    """Load the RSA Public Key from disk."""
    with open(os.path.join(KEY_DIR, "public_key.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


def encrypt_file_hybrid(filename):
    """
    Encrypts a file using the Hybrid Encryption Scheme.
    
    1. Generates a one-time AES session key.
    2. Encrypts the file data with AES.
    3. Encrypts the AES session key with the RSA Public Key.
    4. Saves the encrypted file and the encrypted key to disk.
    
    Args:
        filename (str): The name of the file inside 'test_inputs' to encrypt.
    """
    input_path = os.path.join(INPUT_DIR, filename)
    
    # 1. Generate a temporary AES key (The "Session Key")
    session_key = Fernet.generate_key()
    cipher_suite = Fernet(session_key)

    # 2. Encrypt the actual file content
    with open(input_path, "rb") as f:
        file_data = f.read()
    
    encrypted_file_data = cipher_suite.encrypt(file_data)

    # 3. Load the RSA Public Key to lock the Session Key
    public_key = load_public_key()
    
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Save the artifacts
    # Save the Encrypted Data
    enc_file_path = os.path.join(OUTPUT_DIR, filename + ".enc")
    with open(enc_file_path, "wb") as f:
        f.write(encrypted_file_data)

    # Save the Encrypted Key to decrypt later
    enc_key_path = os.path.join(OUTPUT_DIR, filename + ".key.enc")
    with open(enc_key_path, "wb") as f:
        f.write(encrypted_session_key)

    print(f"Success! File encrypted at: {enc_file_path}")
    print(f"Locked Session Key saved at: {enc_key_path}")


if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa # Imported here for scope
    
    setup_directories()
    
    # 1. Ensure we have an identity
    generate_identity()

    # 2. Create a dummy file in the input folder if it doesn't exist
    test_file = "test_contract.pdf" # Pretending it's a PDF
    test_path = os.path.join(INPUT_DIR, test_file)
    if not os.path.exists(test_path):
        with open(test_path, "wb") as f:
            f.write(b"This file has the analysis of our business alnogside the fieds that we are paning to work on, don't send it to anyone!")
    
    # 3. Perform the Hybrid Encryption
    encrypt_file_hybrid(test_file)