import os
import datetime
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

from src.security.revocation import is_revoked


class HSM:
    """
    Simulated Hardware Security Module.
    • Generate RSA keypair
    • Issue self-signed certificate
    • Store PKCS12 keystore
    • Load identity securely
    """

    @staticmethod
    def generate_identity(username, password, user_dir, ca_dir=None):
        if ca_dir is None:
            ca_dir = user_dir

        os.makedirs(keystore_dir, exist_ok=True)

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_id)
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )

        p12 = pkcs12.serialize_key_and_certificates(
            name=user_id.encode(),
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(password.encode())
        )

        path = os.path.join(keystore_dir, f"{user_id}.p12")

        with open(path, "wb") as f:
            f.write(p12)

        return path


    @staticmethod
    def load_identity(user_id: str, password: str, keystore_dir: str):

        path = os.path.join(keystore_dir, f"{user_id}.p12")

        if not os.path.exists(path):
            raise FileNotFoundError("Identity not found")

        with open(path, "rb") as f:
            data = f.read()

        key, cert, cas = pkcs12.load_key_and_certificates(
            data,
            password.encode()
        )

        # ---------- PKI SECURITY CHECKS ----------

        # 1️ Certificate expiry
        if cert.not_valid_after.replace(tzinfo=None) < datetime.datetime.utcnow():
            raise ValueError("Certificate expired")

        # 2️ Certificate revocation check
        ca_dir = os.path.join(os.path.dirname(keystore_dir), "ca")
        if is_revoked(ca_dir, cert):
            raise ValueError("Certificate revoked")

        return key, cert, cas