import requests
import os
# Note: Ensure 'src.settings' matches your actual config file name (sometimes it is src.config)
from src.settings import SERVER_URL, CERT_PATH, REQUEST_TIMEOUT

"""
Network Interface Module
------------------------
Encapsulates HTTP transport logic for the Secure Remote Storage API.
This module enforces Transport Layer Security (TLS) by verifying the 
server's SSL certificate against the local trusted authority.
"""

def check_server_status():
    """
    Performs a heartbeat check against the remote server's health endpoint.

    This function serves two purposes:
    1. Verifies network connectivity (TCP/IP).
    2. Validates the SSL Handshake to ensure the server identity is trusted.

    Returns:
        bool: True if the server is online and the connection is secure (HTTP 200).
    """
    try:
        print(f"[*] Initiating secure handshake with {SERVER_URL}/health...")
        
        # Request Configuration:
        # - verify=CERT_PATH: Performs strict SSL validation using our local certificate.
        #   This prevents Man-in-the-Middle (MITM) attacks.
        # - timeout: Prevents the client from hanging indefinitely if the server is unresponsive.
        response = requests.get(
            f"{SERVER_URL}/health", 
            verify=CERT_PATH, 
            timeout=REQUEST_TIMEOUT
        )
        return response.status_code == 200
        
    except requests.exceptions.SSLError as e:
        # Catch-all for TLS failures (e.g., Expired Cert, Hostname Mismatch, Untrusted CA).
        print(f"[-] FATAL: SSL Handshake Failed. The server identity could not be verified.\n    Details: {e}")
        return False
    except requests.exceptions.ConnectionError as e:
        # Handles TCP level failures (e.g., Server is down, Firewall blocking port 443).
        print(f"[-] ERROR: Connection Refused. Ensure Docker containers are running.\n    Details: {e}")
        return False
    except Exception as e:
        # Safety net for unexpected runtime exceptions (e.g., File I/O errors).
        print(f"[-] ERROR: Unexpected network exception.\n    Details: {e}")
        return False

def upload_file(filename, file_data):
    """
    Transmits an encrypted binary payload to the secure storage vault.

    Args:
        filename (str): The identifier for the file artifact.
        file_data (bytes): The AES-encrypted binary content.

    Returns:
        requests.Response: The raw response object from the API, or None on failure.
    """
    try:
        # Prepare Multipart/Form-Data payload.
        # This format is required for reliable binary file transmission over HTTP.
        files_payload = {'file': (filename, file_data)}
        
        response = requests.post(
            f"{SERVER_URL}/upload", 
            files=files_payload, 
            verify=CERT_PATH,  # Enforce encryption and identity check
            timeout=REQUEST_TIMEOUT
        )
        return response
    except Exception as e:
        print(f"[-] Upload Operation Failed: {e}")
        return None

def download_file(filename):
    """
    Retrieves an encrypted artifact from the secure storage vault.

    Args:
        filename (str): The identifier of the file to retrieve.

    Returns:
        bytes: The raw encrypted content if successful.
        None: If the file is missing (404) or network fails.
    """
    try:
        url = f"{SERVER_URL}/download/{filename}"
        
        # Sends a Secure GET request.
        # Note: Large file streaming is disabled here for simplicity (content loaded to RAM).
        response = requests.get(
            url, 
            verify=CERT_PATH, 
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            return response.content
        else:
            return None
    except Exception as e:
        print(f"[-] Download Operation Failed: {e}")
        return None
