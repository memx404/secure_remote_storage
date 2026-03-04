import os
from cryptography import x509

def _revoked_path(ca_dir: str) -> str:
    os.makedirs(ca_dir, exist_ok=True)
    return os.path.join(ca_dir, "revoked_serials.txt")

def revoke_cert_serial(ca_dir: str, serial_number: int) -> None:
    path = _revoked_path(ca_dir)
    with open(path, "a", encoding="utf-8") as f:
        f.write(str(serial_number) + "\n")

def is_revoked(ca_dir: str, cert: x509.Certificate) -> bool:
    path = _revoked_path(ca_dir)
    if not os.path.exists(path):
        return False
    serial = str(cert.serial_number)
    with open(path, "r", encoding="utf-8") as f:
        revoked = {line.strip() for line in f if line.strip()}
    return serial in revoked
