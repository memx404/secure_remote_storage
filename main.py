"""
Secure Remote Storage - CLI Entry Point (v3.0 - Network Enabled)
================================================================
Updates:
1. Added 'network' module integration.
2. New 'upload' and 'download' commands in interactive shell.
3. server health check on startup.
"""

import argparse
import sys
import os
import shlex
# Import the new network module
from src import keys, crypto, network

KEY_DIR = "keys"

def setup_env():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

def resolve_single_path(user_path):
    clean_path = user_path.strip().strip('"').strip("'")
    abs_path = os.path.abspath(clean_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")
    return abs_path

# --- EXISTING FUNCTIONS (Generate, Encrypt, Decrypt) ---
def perform_generate():
    print(f"\n[*] Generating Identity in '{KEY_DIR}'...")
    try:
        keys.generate_key_pair(KEY_DIR)
        print("[+] Identity generated successfully.")
    except Exception as e:
        print(f"[-] Error: {e}")

def perform_encrypt(file_path):
    try:
        abs_path = resolve_single_path(file_path)
        input_dir, filename = os.path.split(abs_path)
        print(f"[*] Encrypting '{filename}'...")
        
        pub_key = keys.load_public_key(KEY_DIR)
        crypto.encrypt_file(filename, input_dir, input_dir, pub_key)
        
        print(f"[+] Success. Encrypted to: {abs_path}.enc")
        print(f"    (Don't forget to upload the key too!)")
    except Exception as e:
        print(f"[-] Encryption Failed: {e}")

def perform_decrypt(enc_file, key_file):
    try:
        abs_enc_path = resolve_single_path(enc_file)
        abs_key_path = resolve_single_path(key_file)
        
        print(f"[*] Decrypting target: {os.path.basename(abs_enc_path)}")
        priv_key = keys.load_private_key(KEY_DIR)
        
        output_dir = os.path.dirname(abs_enc_path)
        restored_path = crypto.decrypt_file(abs_enc_path, abs_key_path, output_dir, priv_key)
        print(f"[+] Success: File restored to: {restored_path}")
    except Exception as e:
        print(f"[-] Decryption Failed: {e}")

# --- NEW NETWORK FUNCTIONS ---
def perform_upload(file_path):
    """Handles uploading a local file to the server."""
    try:
        abs_path = resolve_single_path(file_path)
        print(f"[*] Uploading '{os.path.basename(abs_path)}' to server...")
        
        if network.upload_file(abs_path):
            print("[+] Upload Successful!")
        else:
            print("[-] Upload failed (unknown error).")
            
    except Exception as e:
        print(f"[-] Network Error: {e}")

def perform_download(filename):
    """Handles downloading a file from server to current directory."""
    try:
        # Save to the current folder where the user is running the script
        current_dir = os.getcwd()
        print(f"[*] Downloading '{filename}'...")
        
        save_path = network.download_file(filename, current_dir)
        print(f"[+] Download Successful: {save_path}")
        
    except Exception as e:
        print(f"[-] Network Error: {e}")

def perform_check_server():
    """Quick manual health check."""
    if network.check_server_health():
        print("[+] Server is ONLINE and reachable.")
    else:
        print("[-] Server is OFFLINE or unreachable.")

# --- INTERACTIVE SHELL ---
def run_interactive_shell():
    print("=" * 60)
    print("Secure Remote Storage (CLI v3.0)".center(60))
    print("Type 'help' to list commands and 'quit' to exit.".center(60))
    print("=" * 60)

    # Auto-check server status on startup
    print("\n[*] Checking server connection...")
    perform_check_server()

    while True:
        try:
            user_input = input("\nSRS-Shell> ").strip()
            if not user_input: continue

            parts = shlex.split(user_input)
            command = parts[0].lower()
            args = parts[1:]

            if command in ["exit", "quit", "q"]:
                break
            
            elif command == "help":
                print("Commands:")
                print("  generate")
                print("  encrypt <file>")
                print("  decrypt -f <enc_file> -k <key_file>")
                print("  upload <file>")
                print("  download <filename>")
                print("  status (check server)")
                print("  quit")

            elif command == "generate": perform_generate()
            elif command == "encrypt": perform_encrypt(args[0]) if args else print("Usage: encrypt <file>")
            elif command == "upload": perform_upload(args[0]) if args else print("Usage: upload <file>")
            elif command == "download": perform_download(args[0]) if args else print("Usage: download <filename>")
            elif command == "status": perform_check_server()
            
            elif command == "decrypt":
                # Simplified argument parsing for shell
                f_path, k_path = None, None
                if "-f" in args and "-k" in args:
                    try:
                        f_path = args[args.index("-f") + 1]
                        k_path = args[args.index("-k") + 1]
                        perform_decrypt(f_path, k_path)
                    except: print("Error: Check your arguments.")
                else:
                    print("Usage: decrypt -f <file> -k <key>")

            else:
                print(f"Unknown command: '{command}'")

        except Exception as e:
            print(f"[-] Error: {e}")

def main():
    setup_env()
    # For now, we only support interactive mode heavily
    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        perform_generate() # Keep this for CI pipeline smoke test
    else:
        run_interactive_shell()

if __name__ == "__main__":
    main()
