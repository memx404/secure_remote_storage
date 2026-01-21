import os
# Import the refactored modules from the src package
from src import keys, crypto

# Centralized configuration for directory paths
DIRECTORIES = {
    "keys": "keys",
    "input": "test_inputs",
    "output": "test_outputs",
    "restored": "test_restored"
}

def setup():
    """Ensure all required directories exist before execution."""
    for path in DIRECTORIES.values():
        if not os.path.exists(path):
            os.makedirs(path)

    # Create a dummy test file for demonstration
    test_file = os.path.join(DIRECTORIES["input"], "data.txt")
    if not os.path.exists(test_file):
        with open(test_file, "w") as f:
            f.write("CONFIDENTIAL: This data was processed by the refactored engine.")

def run_workflow():
    """Executes the full encryption and decryption lifecycle."""
    print("--- [1] Initialization ---")
    setup()

    # Step 1: Identity Management
    keys.generate_key_pair(DIRECTORIES["keys"])

    # Load keys for the operation
    pub_key = keys.load_public_key(DIRECTORIES["keys"])
    priv_key = keys.load_private_key(DIRECTORIES["keys"])

    target_file = "data.txt"

    # Step 2: Encryption
    print(f"\n--- [2] Encrypting '{target_file}' ---")
    try:
        crypto.encrypt_file(target_file, DIRECTORIES["input"], DIRECTORIES["output"], pub_key)
        print("Encryption successful.")
    except Exception as e:
        print(f"Encryption failed: {e}")

    # Step 3: Decryption
    print(f"\n--- [3] Decrypting '{target_file}' ---")
    try:
        crypto.decrypt_file(target_file, DIRECTORIES["output"], DIRECTORIES["restored"], priv_key)
        print("Decryption successful.")
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    run_workflow()