"""
Core encryption script.

Currently testing basic AES functionality using the cryptography library.
"""

import cryptography

# Trying to setup the cipher
def encrypt_data(data):
    # Using a simple password for now
    key = "temporary_password_123"
    return key + data

print(encrypt_data("Secret Message"))