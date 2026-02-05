import os

"""
Configuration Constants
-----------------------
Defines environment-specific variables for the client application.
"""

# Server Endpoint
# Uses HTTPS protocol (Port 443) to ensure encrypted transport.
SERVER_URL = "https://localhost:443"

# SSL Verification
# Path to the Certificate Authority (CA) bundle or self-signed certificate.
# Required by the 'requests' library to validate the server's identity.
CERT_PATH = os.path.join("nginx", "certs", "server.crt")

# Request Settings
# Timeout in seconds to prevent hanging connections.
REQUEST_TIMEOUT = 10
