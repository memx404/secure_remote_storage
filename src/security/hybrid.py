import os
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.security.hsm import HSM


class HybridCipher:
    """
    HYBRID ENCRYPTION
    -----------------
    - Generates random AES-256 key and encrypts data with AES-GCM
    - Encrypts AES key with recipient's RSA public key (from PKI cert)
    """

    @staticmethod
    def encrypt_data(data: bytes, user_id: str, password: str, keystore_dir: str) -> dict:
        _priv, cert, _cas = HSM.load_identity(user_id, password, keystore_dir)
        pub = cert.public_key()

        # AES key + nonce
        aes_key = os.urandom(32)   # 256-bit
        nonce = os.urandom(12)     # 96-bit nonce for GCM

        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Encrypt AES key using RSA OAEP
        enc_key = pub.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            "enc_key": enc_key.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

    @staticmethod
    def decrypt_data(bundle: dict, user_id: str, password: str, keystore_dir: str) -> bytes:
        priv, _cert, _cas = HSM.load_identity(user_id, password, keystore_dir)

        enc_key = bytes.fromhex(bundle["enc_key"])
        nonce = bytes.fromhex(bundle["nonce"])
        ciphertext = bytes.fromhex(bundle["ciphertext"])

        aes_key = priv.decrypt(
            enc_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
