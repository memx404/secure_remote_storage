import os

# CONFIGURATION SETTINGS
# ----------------------
# Central place for project constants.

SRS_STORAGE_DIR = os.getenv('SRS_STORAGE', 'secure_storage')
SRS_DB_NAME = "srs_db"
SRS_SERVER_URL = "https://localhost:443"

# Paths for Nginx Certificates (used by client validation)
CERT_PATH = os.path.join("nginx", "certs", "server.crt")
