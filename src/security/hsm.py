import os
import datetime
import logging
from typing import Optional, Dict, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from src.security.ca import LocalCA

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SRS_HSM")


class HSM:
    """
    Simulated Hardware Security Module (HSM)
    ---------------------------------------
    - Generates RSA-4096 keypairs
    - Issues CA-signed X.509 certificates (PKI)
    - Stores private key + cert in password-protected PKCS#12 (.p12)
    """

    @staticmethod
    def _p12_path(user_id: str, keystore_dir: str) -> str:
        safe = (user_id or "").strip()
        return os.path.join(keystore_dir, f"{safe}.p12")

    @staticmethod
    def generate_identity(
        user_id: str,
        password: str,
        keystore_dir: str,
        ca_dir: Optional[str] = None,
        *args,
        **kwargs
    ) -> Dict[str, str]:
        """
        Creates a new user identity:
          - RSA-4096 private key
          - CA-signed certificate
          - Saved as <keystore_dir>/<user_id>.p12 (encrypted with password)
        """
        user_id = (user_id or "").strip()
        password = password or ""
        if not user_id or not password:
            raise ValueError("user_id and password are required")

        os.makedirs(keystore_dir, exist_ok=True)

        if not ca_dir:
            ca_dir = os.path.join(os.path.dirname(keystore_dir), "ca")
        os.makedirs(ca_dir, exist_ok=True)

        # 1) Generate RSA 4096-bit key
        logger.info("Generating RSA-4096 keypair for user=%s", user_id)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        # 2) Issue CA-signed certificate 
        ca = LocalCA(ca_dir)
        user_cert = ca.issue_user_cert(
            user_id=user_id,
            public_key=private_key.public_key(),
            days_valid=365
        )

        # 3) Save to PKCS#12
        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=user_id.encode("utf-8"),
            key=private_key,
            cert=user_cert,
            cas=[ca.ca_cert],  
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
        )

        p12_path = HSM._p12_path(user_id, keystore_dir)

        # Safe write
        tmp_path = p12_path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(p12_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, p12_path)

        logger.info("Identity saved: %s", p12_path)
        return {"status": "SUCCESS", "p12_path": p12_path, "ca_dir": ca_dir}

    @staticmethod
    def load_identity(user_id: str, password: str, keystore_dir: str):
       
        user_id = (user_id or "").strip()
        password = password or ""

        p12_path = HSM._p12_path(user_id, keystore_dir)
        if not os.path.exists(p12_path):
            raise FileNotFoundError(f"Identity not found: {p12_path}. Please register first.")

        if os.path.getsize(p12_path) < 50:
            raise ValueError(f"Corrupted/empty PKCS#12 file: {p12_path}. Delete it and re-register.")

        try:
            with open(p12_path, "rb") as f:
                key, cert, cas = pkcs12.load_key_and_certificates(
                    f.read(),
                    password.encode("utf-8")
                )

            if key is None or cert is None:
                raise ValueError("PKCS#12 is missing key/certificate")

            # ✅ Always return 3 values
            return key, cert, cas

        except ValueError:
            raise ValueError(
                "Invalid password or PKCS12 data. "
                "Use the SAME password you used during Register. "
                "If unsure, delete the .p12 and register again."
            )

    @staticmethod
    def load_public_cert_pem(user_id: str, password: str, keystore_dir: str) -> bytes:
        
        _key, cert = HSM.load_identity(user_id, password, keystore_dir)
        return cert.public_bytes(serialization.Encoding.PEM)
