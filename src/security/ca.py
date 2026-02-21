import os
import json
import datetime
from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class LocalCA:
    """
    Local Certificate Authority
    -------------------------------------------------
    - Creates/loads CA private key + CA certificate
    - Issues user certificates
    """

    def __init__(self, ca_dir: str):
        self.ca_dir = ca_dir
        os.makedirs(self.ca_dir, exist_ok=True)

        self.ca_key_path = os.path.join(self.ca_dir, "ca_key.pem")
        self.ca_cert_path = os.path.join(self.ca_dir, "ca_cert.pem")

        self.ca_key, self.ca_cert = self._load_or_create_ca()

    def _load_or_create_ca(self):
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            return ca_key, ca_cert

        # Create CA key
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SRS Local CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"SRS Root CA"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        # Save CA key/cert
        with open(self.ca_key_path, "wb") as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        return ca_key, ca_cert

    def issue_user_cert(self, user_id: str, public_key, days_valid: int = 365) -> x509.Certificate:
        user_id = (user_id or "").strip()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SRS Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"User:{user_id}"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        return cert
