import os
from OpenSSL import crypto

"""
Certificate Authority Utility
-----------------------------
Generates self-signed X.509 certificates for local development environments.
"""

def generate_self_signed_cert(cert_dir="nginx/certs"):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    # Generate 2048-bit RSA Key
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Generate Certificate
    cert = crypto.X509()
    cert.get_subject().C = "NP"
    cert.get_subject().O = "SecureStorage"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    # Save Artifacts
    with open(os.path.join(cert_dir, "server.crt"), "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(os.path.join(cert_dir, "server.key"), "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

if __name__ == "__main__":
    generate_self_signed_cert()

