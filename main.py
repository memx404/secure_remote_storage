"""
Core encryption utility.

This module handles symmetric encryption operations using the Fernet (AES)
standard. It supports both string and binary file encryption, ensuring
compatibility with various file formats.
"""

import os
from cryptography.fernet import Fernet

# Generate a new symmetric key for the current execution session.
# In future iterations, this logic will move to a persistent keystore.
key = Fernet.generate_key()


def encrypt_file(filename):
    """
    Encrypt a specified file and save the output to disk.

    The function utilizes binary mode for file operations to prevent
    encoding errors when processing non-text files (images, PDFs, etc).

    Args:
        filename (str): The path to the file target for encryption.
    """
    cipher = Fernet(key)

    # Open file in binary read mode ('rb') to acquire raw bytes.
    # This prevents encoding errors that occur with non-text files.
    with open(filename, "rb") as f:
        file_data = f.read()

    # Encrypt the byte stream.
    encrypted_data = cipher.encrypt(file_data)

    # Write the ciphertext to a new file using binary write mode ('wb').
    output_filename = filename + ".enc"
    with open(output_filename, "wb") as f:
        f.write(encrypted_data)

    print(f"Encryption successful. Output saved to: {output_filename}")


if __name__ == "__main__":
    print(f"Active Session Key: {key}")

    # Define the directory for test artifacts to keep the root folder clean.
    test_dir = "test_main"

    # Create the directory if it does not already exist.
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)

    # Define the path for the dummy test file.
    test_file_path = os.path.join(test_dir, "test_doc.txt")

    # Initialize a test file to verify logic.
    with open(test_file_path, "w") as f:
        f.write("Project documentation: Confidential.")

    # Execute encryption on the test file.
    encrypt_file(test_file_path)