import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def secure_delete(file_path):
    """
    Overwrites a file with zeros before deleting it to prevent recovery.
    This simulates a 'shred' operation.
    """
    try:
        # Get file size
        length = os.path.getsize(file_path)
        # Overwrite with zeros
        with open(file_path, "wb") as f:
            f.write(b'\x00' * length)
        # Delete the file
        os.remove(file_path)
    except Exception as e:
        print(f"[-] Warning: Could not securely wipe {file_path}: {e}")

def encrypt_file(filename, input_dir, output_dir, public_key):
    """
    Encrypts a file and WIPES the original.
    1. Generates AES Key.
    2. Encrypts content.
    3. Saves .enc and .key.enc files.
    4. Securely deletes the original input file.
    """
    # Generate a random 256-bit (32 byte) AES key and 128-bit (16 byte) IV
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Construct full file path
    input_path = os.path.join(input_dir, filename)
    
    # Read the original data
    with open(input_path, "rb") as f:
        data = f.read()

    # --- AES Encryption (Symmetric) ---
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the data to be a multiple of 128 bits (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()

    # --- Write the Encrypted File (.enc) ---
    # We write the IV first (unencrypted), then the data
    enc_filename = filename + ".enc"
    enc_path = os.path.join(output_dir, enc_filename)
    
    with open(enc_path, "wb") as f:
        f.write(iv + encrypted_content)

    # --- RSA Encryption of AES Key (Asymmetric) ---
    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # --- Write the Encrypted Key File (.key.enc) ---
    key_enc_filename = filename + ".key.enc"
    key_path = os.path.join(output_dir, key_enc_filename)
    
    with open(key_path, "wb") as f:
        f.write(encrypted_key)

    # --- DESTRUCTIVE STEP: Wipe Original ---
    secure_delete(input_path)
    
    return True

def decrypt_file(enc_file_path, key_file_path, output_dir, private_key):
    """
    Decrypts a specific file using a specific encrypted key.
    
    Args:
        enc_file_path (str): Full path to the .enc file.
        key_file_path (str): Full path to the .key.enc file.
        output_dir (str): Where to save the restored file.
        private_key: Loaded RSA private key object.
    """
    # 1. Read the Encrypted AES Key
    with open(key_file_path, "rb") as f:
        encrypted_aes_key = f.read()

    # 2. Decrypt the AES Key using RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Read the Encrypted Content
    with open(enc_file_path, "rb") as f:
        file_content = f.read()

    # Extract IV (first 16 bytes) and ciphertext
    iv = file_content[:16]
    ciphertext = file_content[16:]

    # 4. Decrypt the Content using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # 5. Remove Padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # 6. Restore Original Filename (Remove .enc extension)
    # Get just the filename from the path
    enc_filename = os.path.basename(enc_file_path)
    if enc_filename.endswith(".enc"):
        original_filename = enc_filename[:-4] # Strip last 4 chars (.enc)
    else:
        original_filename = "restored_" + enc_filename

    output_path = os.path.join(output_dir, original_filename)

    with open(output_path, "wb") as f:
        f.write(data)
        
    return output_path
