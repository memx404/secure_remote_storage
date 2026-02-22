import os

# =========================
# Core runtime configuration
# =========================

SERVER_URL = os.getenv("SRS_SERVER_URL", "https://localhost")

CERT_PATH = os.getenv("SRS_CERT_PATH", "nginx/certs/server.crt")

REQUEST_TIMEOUT = float(os.getenv("SRS_REQUEST_TIMEOUT", "10"))

SRS_STORAGE = os.getenv("SRS_STORAGE", "secure_storage")
