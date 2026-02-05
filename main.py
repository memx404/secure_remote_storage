import sys
import os
import shlex
from src import keys, crypto, network

KEY_DIR = "keys"

def setup_env():
    """Ensures necessary directories exist."""
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

def resolve_single_path(user_path):
    """Helper to fix path issues (removes quotes, checks existence)."""
    clean_path = user_path.strip().strip('"').strip("'")
    abs_path = os.path.abspath(clean_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")
    return abs_path

# --- NETWORK COMMANDS (HTTPS Enabled) ---
def perform_check_server():
    """Checks if the secure HTTPS server is reachable."""
    # Updated to match src/network.py function name
    if network.check_server_status():
        print("[+] Server is ONLINE and Secure (HTTPS).")
    else:
        print("[-] Server is OFFLINE or Certificate Invalid.")

def perform_upload(file_path):
    """Uploads a file using the secure network module."""
    try:
        abs_path = resolve_single_path(file_path)
        filename = os.path.basename(abs_path)
        
        print(f"[*] Reading '{filename}'...")
        with open(abs_path, "rb") as f:
            file_data = f.read()
            
        print(f"[*] Uploading encrypted file to server...")
        res = network.upload_file(filename, file_data)
        
        if res and res.status_code == 200:
            print(f"[+] Success! Server stored file as: {filename}")
        else:
            print("[-] Upload Failed. Check server logs.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

def perform_download(filename):
    """Downloads a file securely from the server."""
    try:
        print(f"[*] Requesting '{filename}' from server...")
        file_content = network.download_file(filename)
        
        if file_content:
            save_path = os.path.join(os.getcwd(), f"downloaded_{filename}")
            with open(save_path, "wb") as f:
                f.write(file_content)
            print(f"[+] Download Successful! Saved to: {save_path}")
        else:
            print("[-] Download Failed (File not found or Server Error).")
            
    except Exception as e:
        print(f"[-] Network Error: {e}")

# --- CRYPTO COMMANDS ---
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
    except Exception as e:
        print(f"[-] Encryption Failed: {e}")

def perform_decrypt(enc_file, key_file):
    try:
        abs_enc_path = resolve_single_path(enc_file)
        # Default key location if not provided is implied to be handled by user
        abs_key_path = resolve_single_path(key_file)
        
        print(f"[*] Decrypting target: {os.path.basename(abs_enc_path)}")
        priv_key = keys.load_private_key(KEY_DIR)
        
        output_dir = os.path.dirname(abs_enc_path)
        restored_path = crypto.decrypt_file(abs_enc_path, abs_key_path, output_dir, priv_key)
        print(f"[+] Success: File restored to: {restored_path}")
    except Exception as e:
        print(f"[-] Decryption Failed: {e}")

# --- INTERACTIVE SHELL ---
def run_interactive_shell():
    print("=" * 60)
    print("Secure Remote Storage (CLI v3.0 - HTTPS Enabled)".center(60))
    print("Type 'help' to list commands and 'quit' to exit.".center(60))
    print("=" * 60)

    # Auto-check server status on startup
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
                print("\nAvailable Commands:")
                print("  status              - Check HTTPS connection")
                print("  generate            - Create RSA keys")
                print("  encrypt <file>      - Encrypt local file")
                print("  upload <file>       - Upload encrypted file")
                print("  download <name>     - Download file")
                print("  decrypt -f <file> -k <key> - Decrypt file")
                print("  quit                - Exit")

            elif command == "status": perform_check_server()
            elif command == "generate": perform_generate()
            elif command == "encrypt": perform_encrypt(args[0]) if args else print("Usage: encrypt <file>")
            elif command == "upload": perform_upload(args[0]) if args else print("Usage: upload <file>")
            elif command == "download": perform_download(args[0]) if args else print("Usage: download <filename>")
            
            elif command == "decrypt":
                if "-f" in args and "-k" in args:
                    try:
                        f_idx = args.index("-f") + 1
                        k_idx = args.index("-k") + 1
                        perform_decrypt(args[f_idx], args[k_idx])
                    except IndexError:
                        print("[-] Error: Missing file paths.")
                else:
                    print("Usage: decrypt -f <file.enc> -k <private_key.pem>")

            else:
                print(f"[-] Unknown command: '{command}'")

        except Exception as e:
            print(f"[-] Error: {e}")

def main():
    setup_env()
    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        perform_generate()
    else:
        run_interactive_shell()

if __name__ == "__main__":
    main()
