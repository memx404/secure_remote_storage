import os
import pytest
from src import crypto, keys

def test_encryption_and_decryption_flow(tmp_path):
    # 1. Setup Environment
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "input" # In your new code, output is same as input
    input_dir.mkdir()
    
    # 2. Create Dummy File
    filename = "secret_data.txt"
    file_path = input_dir / filename
    original_content = b"This is top secret data."
    
    with open(file_path, "wb") as f:
        f.write(original_content)

    # 3. Generate Keys
    keys.generate_key_pair(str(input_dir))
    pub_key = keys.load_public_key(str(input_dir))
    priv_key = keys.load_private_key(str(input_dir))

    # 4. Encrypt (This should DELETE the original file)
    crypto.encrypt_file(filename, str(input_dir), str(output_dir), pub_key)

    # CHECK: Did the original file disappear? (Secure Wipe)
    assert not os.path.exists(file_path)

    # CHECK: Did the .enc files appear?
    enc_file = input_dir / (filename + ".enc")
    key_file = input_dir / (filename + ".key.enc")
    assert os.path.exists(enc_file)
    assert os.path.exists(key_file)

    # 5. Decrypt (Using explicit paths)
    # Output dir for restoration
    restore_dir = input_dir / "restored"
    restore_dir.mkdir()

    crypto.decrypt_file(str(enc_file), str(key_file), str(restore_dir), priv_key)

    # CHECK: Is the file back?
    restored_file = restore_dir / filename
    assert os.path.exists(restored_file)
    
    # CHECK: Is the content correct?
    with open(restored_file, "rb") as f:
        restored_content = f.read()
    
    assert restored_content == original_content
