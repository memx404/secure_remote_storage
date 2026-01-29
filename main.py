import argparse
import sys
import os
import shlex
from src import keys, crypto

# Default "Home" for keys
KEY_DIR = "keys"

def setup_env():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

def resolve_single_path(user_path):
    """Helper to clean and validate a single file path."""
    clean_path = user_path.strip().strip('"').strip("'")
    abs_path = os.path.abspath(clean_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")
    return abs_path

def perform_generate():
    print(f"\n[*] Generating Identity in '{KEY_DIR}'...")
    try:
        keys.generate_key_pair(KEY_DIR)
        print("[+] Identity generated successfully.")
    except Exception as e:
        print(f"[-] Error: {e}")

def perform_encrypt(file_path):
    try:
        # Resolve full path
        abs_path = resolve_single_path(file_path)
        input_dir, filename = os.path.split(abs_path)
        
        print(f"[*] Encrypting '{filename}'...")
        
        pub_key = keys.load_public_key(KEY_DIR)
        
        # Encrypt (Output goes to SAME folder)
        # This function deletes the original file inside crypto.py
        crypto.encrypt_file(filename, input_dir, input_dir, pub_key)
        
        print(f"[+] Success. Encrypted to:")
        print(f"    -> {abs_path}.enc")
        print(f"    -> {abs_path}.key.enc")
    except Exception as e:
        print(f"[-] Encryption Failed: {e}")

def perform_decrypt(enc_file, key_file):
    try:
        # Resolve both paths
        abs_enc_path = resolve_single_path(enc_file)
        abs_key_path = resolve_single_path(key_file)
        
        print(f"[*] Decrypting target: {os.path.basename(abs_enc_path)}")

        priv_key = keys.load_private_key(KEY_DIR)
        
        # Determine output directory (Same as encrypted file location)
        output_dir = os.path.dirname(abs_enc_path)

        # Decrypt
        restored_path = crypto.decrypt_file(abs_enc_path, abs_key_path, output_dir, priv_key)
        print(f"[+] Success: File restored to: {restored_path}")
    except Exception as e:
        print(f"[-] Decryption Failed: {e}")

# --- INTERACTIVE SHELL ---
def run_interactive_shell():
    # Header
    print("=" * 60)
    print("Secure Remote Storage".center(60))
    print("Type 'help' to list commands and 'quit' to exit.".center(60))
    print("-" * 50)

    while True:
        try:
            user_input = input("\n> ").strip()
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
                print("  quit")

            elif command == "generate":
                perform_generate()

            elif command == "encrypt":
                if len(args) < 1:
                    print("Error: Usage: encrypt <file_path>")
                else:
                    perform_encrypt(args[0])

            elif command == "decrypt":
                # Quick parser for the shell args
                f_path = None
                k_path = None
                
                if "-f" in args and "-k" in args:
                    try:
                        f_index = args.index("-f") + 1
                        k_index = args.index("-k") + 1
                        f_path = args[f_index]
                        k_path = args[k_index]
                    except IndexError:
                        print("Error: Missing argument after flag.")
                        continue
                else:
                    print("Error: Usage: decrypt -f <enc_file> -k <key_file>")
                    continue

                if f_path and k_path:
                    perform_decrypt(f_path, k_path)

            else:
                print(f"Unknown command: '{command}'")

        except Exception as e:
            print(f"[-] Shell Error: {e}")

# --- ONE-SHOT MODE ---
def main():
    setup_env()

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="SRS Security Tool")
        subparsers = parser.add_subparsers(dest="command")

        # Generate
        subparsers.add_parser("generate", help="Generate Keys")
        
        # Encrypt
        enc = subparsers.add_parser("encrypt", help="Encrypt and Wipe File")
        enc.add_argument("--file", required=True)

        # Decrypt
        dec = subparsers.add_parser("decrypt", help="Decrypt specific target")
        dec.add_argument("-f", "--file", required=True, help="Path to .enc file")
        dec.add_argument("-k", "--key", required=True, help="Path to .key.enc file")

        args = parser.parse_args()

        if args.command == "generate": perform_generate()
        elif args.command == "encrypt": perform_encrypt(args.file)
        elif args.command == "decrypt": perform_decrypt(args.file, args.key)
    else:
        run_interactive_shell()

if __name__ == "__main__":
    main()