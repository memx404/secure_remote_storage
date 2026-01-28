import os
import pytest
from src import keys

def test_key_generation(tmp_path):
    """Verify that RSA keys are generated in the specified directory."""
    # tmp_path is a temporary folder provided by pytest that auto-deletes
    keys_dir = tmp_path / "keys"
    
    # Run the function
    keys.generate_key_pair(str(keys_dir), password=b"test_pass")
    
    # Check if files were created
    assert os.path.exists(keys_dir / "private_key.pem")
    assert os.path.exists(keys_dir / "public_key.pem")

def test_key_loading(tmp_path):
    """Verify that generated keys can be loaded back into memory."""
    keys_dir = tmp_path / "keys"
    password = b"test_pass"
    
    # Setup: Generate keys first
    keys.generate_key_pair(str(keys_dir), password=password)
    
    # Test: Load the keys
    priv_key = keys.load_private_key(str(keys_dir), password=password)
    pub_key = keys.load_public_key(str(keys_dir))
    
    # Assertions: Verify objects are not Empty/None
    assert priv_key is not None
    assert pub_key is not None

def test_load_key_wrong_password(tmp_path):
    """Ensure loading fails securely with incorrect password."""
    keys_dir = tmp_path / "keys"
    keys.generate_key_pair(str(keys_dir), password=b"correct_pass")
    
    # Verify that using the wrong password raises a ValueError
    with pytest.raises(ValueError):
        keys.load_private_key(str(keys_dir), password=b"WRONG_PASS")