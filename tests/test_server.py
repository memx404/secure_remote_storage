import io
import os
import uuid
import pytest
from server.app import app

def _nonce():
    return str(uuid.uuid4())

@pytest.fixture
def client(tmp_path):
    os.environ["SRS_STORAGE"] = str(tmp_path)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def test_health_check(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200

def test_protected_upload_requires_token(client):
    # Missing token => 401
    data = {"password": "x", "file": (io.BytesIO(b"t"), "t.txt")}
    resp = client.post("/api/upload", data=data, content_type="multipart/form-data",
                       headers={"X-Request-Id": _nonce()})
    assert resp.status_code in (401, 400)
