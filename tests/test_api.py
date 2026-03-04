import os
import importlib
import io
import pytest
import uuid


def _app():
    mod = importlib.import_module("server.app")
    return mod.app


def _nonce():
    return str(uuid.uuid4())


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    tmp_root = tmp_path_factory.mktemp("srs_test_storage")
    os.environ["SRS_STORAGE"] = str(tmp_root)

    app = _app()
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def _register(client, user_id, password):
    return client.post("/api/register", json={"user_id": user_id, "password": password})


def _login(client, user_id, password):
    r = client.post("/api/login", json={"user_id": user_id, "password": password}, headers={"X-Request-Id": _nonce()})
    return r


def _auth(token):
    return {"Authorization": f"Bearer {token}", "X-Request-Id": _nonce()}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_upload_and_list_files(client):
    user_id = "vaultuser@gmail.com"
    password = "VaultPass@123!"

    assert _register(client, user_id, password).status_code in (200, 201)
    lr = _login(client, user_id, password)
    assert lr.status_code == 200
    token = lr.get_json()["token"]

    data = {"password": password, "file": (io.BytesIO(b"vault content"), "demo.txt")}
    up = client.post("/api/upload", data=data, content_type="multipart/form-data", headers=_auth(token))
    assert up.status_code in (200, 201)

    ls = client.post("/api/files", json={}, headers=_auth(token))
    assert ls.status_code == 200
    files = ls.get_json()["files"]
    assert any(f["filename"] == "demo.txt" for f in files)


def test_decrypt_download_returns_file(client):
    user_id = "decuser@gmail.com"
    password = "DecPass@123!"

    assert _register(client, user_id, password).status_code in (200, 201)
    lr = _login(client, user_id, password)
    token = lr.get_json()["token"]

    data = {"password": password, "file": (io.BytesIO(b"TOP_SECRET"), "secret.txt")}
    up = client.post("/api/upload", data=data, content_type="multipart/form-data", headers=_auth(token))
    assert up.status_code in (200, 201)
    file_id = up.get_json()["file_id"]

    dec = client.post(f"/api/decrypt/{file_id}", data={"password": password},
                      content_type="multipart/form-data", headers=_auth(token))
    assert dec.status_code == 200
    assert dec.data == b"TOP_SECRET"
