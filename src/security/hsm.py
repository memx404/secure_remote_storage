import os
from datetime import datetime, timedelta
from typing import Optional, Tuple, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


class HSM:
    @staticmethod
    def generate_identity(
        user_id: str,
        password: str,
        keystore_dir: str,
        ca_dir: Optional[str] = None,
    ) -> Tuple[str, str]:
        
        if ca_dir is None:
            ca_dir = keystore_dir

        os.makedirs(keystore_dir, exist_ok=True)
        os.makedirs(ca_dir, exist_ok=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user_id)])
        issuer = subject

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )

        p12_path = os.path.join(keystore_dir, f"{user_id}.p12")
        p12_data = pkcs12.serialize_key_and_certificates(
            name=user_id.encode(),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
        )
        with open(p12_path, "wb") as f:
            f.write(p12_data)

        cert_pem_path = os.path.join(ca_dir, f"{user_id}.crt")
        with open(cert_pem_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return p12_path, cert_pem_path

    @staticmethod
    def load_identity(
        user_id: str,
        password: str,
        keystore_dir: str,
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, List[x509.Certificate]]:
        
        p12_path = os.path.join(keystore_dir, f"{user_id}.p12")
        if not os.path.exists(p12_path):
            raise FileNotFoundError(f"Keystore not found: {p12_path}")

        with open(p12_path, "rb") as f:
            p12_bytes = f.read()

        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            data=p12_bytes,
            password=password.encode(),
        )

        if private_key is None or cert is None:
            raise ValueError("Invalid keystore or wrong password")

        ca_list = list(additional_certs) if additional_certs else []
        return private_key, cert, ca_list
