import requests
import os

SERVER_URL = "http://127.0.0.1:5000"

def check_server_health():
    """Returns True if server is online."""
    try:
        resp = requests.get(f"{SERVER_URL}/health", timeout=2)
        return resp.status_code == 200
    except requests.RequestException:
        return False

def upload_file(filepath):
    """Uploads a file to the server."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, 'rb') as f:
        files = {'file': f}
        resp = requests.post(f"{SERVER_URL}/upload", files=files)

    if resp.status_code != 201:
        raise Exception(f"Upload failed: {resp.text}")
    return True

def download_file(filename, save_dir):
    """Downloads a file from the server."""
    resp = requests.get(f"{SERVER_URL}/download/{filename}", stream=True)
    if resp.status_code == 200:
        save_path = os.path.join(save_dir, filename)
        with open(save_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        return save_path
    else:
        raise Exception(f"Download failed: {resp.status_code}")
