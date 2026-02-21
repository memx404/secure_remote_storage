from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from src.security.hsm import HSM

class Signer:
    """
    DIGITAL SIGNATURE ENGINE
    ------------------------
    SHA-256 + RSA-PSS signatures using user's PKI private key.
    """

    @staticmethod
    def sign_data(data: bytes, user_id: str, password: str, keystore_dir: str) -> bytes:
        private_key, _cert, _cas = HSM.load_identity(user_id, password, keystore_dir)

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, user_id: str, password: str, keystore_dir: str) -> bool:
        try:
            _private_key, cert, _cas = HSM.load_identity(user_id, password, keystore_dir)
            public_key = cert.public_key()

            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
