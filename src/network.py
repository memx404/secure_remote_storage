import os
import uuid
import requests
from typing import Optional, Dict, Any

from src.settings import SERVER_URL, REQUEST_TIMEOUT

API_PREFIX = os.getenv("SRS_API_PREFIX", "/api")


def _api_url(path: str) -> str:
   
    base = SERVER_URL.rstrip("/")
    prefix = API_PREFIX.strip("/")
    endpoint = path.strip("/")
    return f"{base}/{prefix}/{endpoint}"


def _nonce_headers(token: Optional[str] = None, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
   
    headers = {"X-Request-Id": str(uuid.uuid4())}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers



def health_check() -> Dict[str, Any]:
   
    r = requests.get(_api_url("/health"), timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


def register(user_id: str, password: str) -> Dict[str, Any]:
    
    payload = {"user_id": user_id, "password": password}
    r = requests.post(
        _api_url("/register"),
        json=payload,
        headers=_nonce_headers(extra={"Content-Type": "application/json"}),
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def login(user_id: str, password: str) -> str:
    
    payload = {"user_id": user_id, "password": password}
    r = requests.post(
        _api_url("/login"),
        json=payload,
        headers=_nonce_headers(extra={"Content-Type": "application/json"}),
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("error", "Login failed"))
    token = data.get("token")
    if not token:
        raise RuntimeError("Login ok but no token returned")
    return token


def list_files(token: str) -> Dict[str, Any]:
    
    r = requests.post(
        _api_url("/files"),
        json={},
        headers=_nonce_headers(token=token, extra={"Content-Type": "application/json"}),
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def upload_file(token: str, password: str, file_path: str) -> Dict[str, Any]:
    
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        data = {"password": password}

        r = requests.post(
            _api_url("/upload"),
            files=files,
            data=data,
            headers=_nonce_headers(token=token),
            timeout=REQUEST_TIMEOUT,
        )
    r.raise_for_status()
    return r.json()


def decrypt_download(token: str, password: str, file_id: str, output_path: str) -> None:
    
    data = {"password": password}
    r = requests.post(
        _api_url(f"/decrypt/{file_id}"),
        data=data,
        headers=_nonce_headers(token=token),
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()

    with open(output_path, "wb") as out:
        out.write(r.content)


def delete_file(token: str, file_id: str) -> Dict[str, Any]:
    
    r = requests.post(
        _api_url(f"/delete/{file_id}"),
        headers=_nonce_headers(token=token),
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()
