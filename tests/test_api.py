import os
import importlib
from pathlib import Path

import pytest


def _load_flask_app():
    """
    Tries common patterns:
    1) app.py with `app = Flask(...)`
    2) app.py with `create_app()`
    """
    mod = importlib.import_module("app")

    if hasattr(mod, "create_app") and callable(mod.create_app):
        return mod.create_app()

    if hasattr(mod, "app"):
        return mod.app

    raise RuntimeError("Could not find Flask app. Expected `app` or `create_app()` in app.py")


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    """
    Creates a Flask test client with isolated storage.
    Mongo is provided by GitHub Actions service in CI.
    """
    tmp_root = tmp_path_factory.mktemp("srs_test_storage")
    os.environ["SRS_STORAGE"] = str(tmp_root)

    os.environ["MONGO_INITDB_ROOT_PASSWORD"] = os.environ.get("MONGO_INITDB_ROOT_PASSWORD", "securepassword123")

    app = _load_flask_app()
    app.config.update(TESTING=True)

    with app.test_client() as c:
        yield c


def _register(client, user_id="test1@gmail.com", password="TestPass@123"):
    return client.post("/api/register", json={"user_id": user_id, "password": password})


def _upload(client, user_id="test1@gmail.com", password="TestPass@123", filename="demo.txt", content=b"hello"):
    data = {
        "user_id": user_id,
        "password": password,
    }

    data["file"] = (content, filename)
    return client.post("/api/upload", data=data, content_type="multipart/form-data")


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["status"] == "OK"


def test_register_creates_identity(client):
    r = _register(client)
    assert r.status_code in (200, 201)
    body = r.get_json()
    assert body["ok"] is True


def test_sign_and_verify_roundtrip(client):
    user_id = "siguser@gmail.com"
    password = "SigPass@123"

    r = _register(client, user_id, password)
    assert r.status_code in (200, 201)

    # Sign
    sign_data = {
        "user_id": user_id,
        "password": password,
        "file": (b"message-to-sign", "msg.txt"),
    }
    r1 = client.post("/api/sign", data=sign_data, content_type="multipart/form-data")
    assert r1.status_code == 200
    j1 = r1.get_json()
    assert j1["ok"] is True
    assert isinstance(j1.get("signature_hex"), str)
    assert len(j1["signature_hex"]) > 10

    # Verify
    verify_data = {
        "user_id": user_id,
        "password": password,
        "signature": j1["signature_hex"],
        "file": (b"message-to-sign", "msg.txt"),
    }
    r2 = client.post("/api/verify", data=verify_data, content_type="multipart/form-data")
    assert r2.status_code == 200
    j2 = r2.get_json()
    assert j2["ok"] is True
    assert j2["valid"] is True


def test_upload_and_list_files(client):
    user_id = "vaultuser@gmail.com"
    password = "VaultPass@123"

    r = _register(client, user_id, password)
    assert r.status_code in (200, 201)

    r_up = _upload(client, user_id, password, "demo.txt", b"vault content")
    assert r_up.status_code in (200, 201)
    j_up = r_up.get_json()
    assert j_up["ok"] is True
    assert "file_id" in j_up
    assert j_up["filename"] == "demo.txt"

    # list
    r_list = client.post("/api/files", json={"user_id": user_id, "password": password})
    assert r_list.status_code == 200
    j_list = r_list.get_json()
    assert j_list["ok"] is True
    assert isinstance(j_list.get("files"), list)
    assert any(x.get("filename") == "demo.txt" for x in j_list["files"])


def test_decrypt_download_returns_file(client):
    
    user_id = "decuser@gmail.com"
    password = "DecPass@123"

    r = _register(client, user_id, password)
    assert r.status_code in (200, 201)

    r_up = _upload(client, user_id, password, "secret.txt", b"TOP_SECRET")
    assert r_up.status_code in (200, 201)
    file_id = r_up.get_json()["file_id"]

    # decrypt endpoint returns a file blob
    r_dec = client.post(f"/api/decrypt/{file_id}", data={"user_id": user_id, "password": password})
    assert r_dec.status_code == 200
    assert r_dec.data == b"TOP_SECRET"
