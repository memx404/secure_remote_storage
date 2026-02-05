import requests
import os
from src.settings import SERVER_URL, CERT_PATH, REQUEST_TIMEOUT

"""
Network Client Module
---------------------
Encapsulates HTTP methods for communicating with the Secure Remote Storage API.
enforces SSL verification using the locally generated certificate.
"""

def check_server_status():
    """
    Performs a health check on the remote server.

    Sends a GET request to the root endpoint to verify connectivity
    and SSL handshake validation.

    Returns:
        bool: True if server responds with HTTP 200, False otherwise.
    """
    try:
        print(f"[*] Connecting to {SERVER_URL}/health using cert: {CERT_PATH}")
        # verify=CERT_PATH forces validation against our self-signed cert.
        response = requests.get(
            f"{SERVER_URL}/health", 
            verify=False, 
            timeout=REQUEST_TIMEOUT
        )
        return response.status_code == 200
    except requests.exceptions.SSLError as e:
        # Captures specific SSL errors (e.g., untrusted cert, wrong hostname).
        print(f"[-] SSL ERROR: {e}") # <--- TELLS US IF CERT IS BAD
        return False
    except requests.exceptions.ConnectionError as e:
        # Captures general connectivity issues (e.g., server down, DNS failure).
        print(f"[-] CONNECTION ERROR: {e}") # <--- TELLS US IF PORT IS BLOCKED
        return False
    except Exception as e:
        # Catch-all for unexpected runtime errors during network I/O.
        print(f"[-] UNKNOWN ERROR: {e}") # <--- TELLS US IF FILE IS MISSING
        return False

def upload_file(filename, file_data):
    """
    Transmits an encrypted binary file to the storage server.

    Args:
        filename (str): The name of the file to be stored on the server.
        file_data (bytes): The raw binary content of the encrypted file.

    Returns:
        requests.Response: The HTTP response object if successful.
        None: If the transfer fails due to network or SSL errors.
    """
    try:
        # Multipart-encoded file payload
        files_payload = {'file': (filename, file_data)}
        
        response = requests.post(
            f"{SERVER_URL}/upload", 
            files=files_payload, 
            verify=False,
            timeout=REQUEST_TIMEOUT
        )
        return response
    except Exception as e:
        # Logs the specific exception message to console for debugging context.
        print(f"[-] Network Exception during upload: {e}")
        return None

def download_file(filename):
    """
    Retrieves a specific file from the remote storage.

    Args:
        filename (str): The identifier of the file to retrieve.

    Returns:
        bytes: The binary content of the file if found.
        None: If the file does not exist or network error occurs.
    """
    try:
        url = f"{SERVER_URL}/download/{filename}"
        
        # Stream=False ensures we load the file into memory immediately (ok for small files).
        response = requests.get(
            url, 
            verify=False, 
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            return response.content
        else:
            return None
    except Exception as e:
        print(f"[-] Network Exception during download: {e}")
        return None
