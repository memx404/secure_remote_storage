import os
from OpenSSL import crypto

"""
Certificate Authority (CA) Generator Utility
--------------------------------------------
Automates the creation of a self-signed X.509 certificate for the local development environment.
This script acts as the Root CA, generating cryptographic assets required for
TLS/SSL termination at the Nginx reverse proxy level.
"""

def generate_self_signed_cert(cert_dir="nginx/certs"):
    """
    Generates a 2048-bit RSA key pair and a compatible X.509 certificate.
    
    The certificate includes Subject Alternative Name (SAN) extensions to 
    ensure strict hostname validation passes in modern Python clients and browsers.

    Args:
        cert_dir (str): Target directory for artifact persistence. Defaults to 'nginx/certs'.
    """
    # Ensure the output directory exists to prevent I/O errors during write operations.
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    # 1. Private Key Generation
    # Uses RSA algorithm with a 2048-bit key length.
    # This provides a standard balance between security and handshake performance.
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # 2. Certificate Construction
    cert = crypto.X509()
    
    # Configure Distinguished Name (DN) fields for the issuer and subject.
    cert.get_subject().C = "NP"             # Country Name
    cert.get_subject().O = "SecureStorage"  # Organization Name
    cert.get_subject().CN = "localhost"     # Common Name (Primary Hostname)
    
    # Set Metadata: Serial number and validity period (1 year).
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    
    # Self-Signing: Issuer and Subject are identical.
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)

    # --- CRITICAL CONFIGURATION: Subject Alternative Name (SAN) ---
    # Modern TLS clients (including Python's `ssl` module) require the SAN extension
    # to explicitly authorize the hostname and IP address.
    # Without this, clients will raise a 'Hostname Mismatch' error.
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, b"DNS:localhost, IP:127.0.0.1")
    ])
    # ----------------------------------------------------------------

    # Sign the certificate using the private key and SHA-256 digest algorithm.
    cert.sign(k, 'sha256')

    # 3. Artifact Persistence
    # Write the public certificate (safe to distribute).
    with open(os.path.join(cert_dir, "server.crt"), "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    # Write the private key (Must remain secure on the server).
    with open(os.path.join(cert_dir, "server.key"), "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    print(f"[+] SSL Infrastructure initialized successfully in: {cert_dir}")

if __name__ == "__main__":
    generate_self_signed_cert()
