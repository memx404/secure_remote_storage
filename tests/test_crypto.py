import os
import pytest
from src import keys, crypto

def test_encryption_workflow(tmp_path):
    """Verify that a file can be encrypted and artifacts are created."""
    # Setup workspace
    workspace = tmp_path / "workspace"
    input_dir = workspace / "input"
    output_dir = workspace / "output"
    key_dir = workspace / "keys"
    
    # Create structure
    for d in [input_dir, output_dir, key_dir]:
        os.makedirs(d)
        
    # Create dummy file
    filename = "secret.txt"
    with open(input_dir / filename, "wb") as f:
        f.write(b"Top Secret Data")
        
    # Generate Identity
    keys.generate_key_pair(str(key_dir))
    pub_key = keys.load_public_key(str(key_dir))
    
    # Run Encryption
    result = crypto.encrypt_file(filename, str(input_dir), str(output_dir), pub_key)
    
    assert result is True
    assert os.path.exists(output_dir / (filename + ".enc"))
    assert os.path.exists(output_dir / (filename + ".key.enc"))

def test_decryption_workflow(tmp_path):
    """Verify the full cycle: Encrypt -> Decrypt -> Compare Data."""
    # Setup workspace
    workspace = tmp_path / "workspace"
    input_dir = workspace / "input"
    output_dir = workspace / "output"
    restored_dir = workspace / "restored"
    key_dir = workspace / "keys"
    
    for d in [input_dir, output_dir, restored_dir, key_dir]:
        os.makedirs(d)
        
    filename = "data.txt"
    original_content = b"This is a critical test."
    with open(input_dir / filename, "wb") as f:
        f.write(original_content)
        
    # Identity & Encrypt
    keys.generate_key_pair(str(key_dir))
    pub_key = keys.load_public_key(str(key_dir))
    priv_key = keys.load_private_key(str(key_dir))
    
    crypto.encrypt_file(filename, str(input_dir), str(output_dir), pub_key)
    
    # Run Decryption
    crypto.decrypt_file(filename, str(output_dir), str(restored_dir), priv_key)
    
    # Verify Integrity
    with open(restored_dir / filename, "rb") as f:
        restored_content = f.read()
        
    assert restored_content == original_content

def test_encrypt_missing_file(tmp_path):
    """Ensure proper error handling when input file is missing."""
    workspace = tmp_path / "workspace"
    key_dir = workspace / "keys"
    os.makedirs(key_dir)
    
    keys.generate_key_pair(str(key_dir))
    pub_key = keys.load_public_key(str(key_dir))
    
    # Verify FileNotFoundError is raised
    with pytest.raises(FileNotFoundError):
        crypto.encrypt_file("ghost.txt", str(workspace), str(workspace), pub_key)