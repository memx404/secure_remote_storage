import io
import os
import pytest
from server.app import app


@pytest.fixture
def client(tmp_path):
    os.environ["SRS_STORAGE"] = str(tmp_path)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health_check(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_upload_flow(client):
    reg = client.post("/api/register", json={"user_id": "ci_user", "password": "ci_pass"})
    assert reg.status_code in (200, 201)

    data = {
        "user_id": "ci_user",
        "password": "ci_pass",
        "file": (io.BytesIO(b"test data"), "test.txt"),
    }
    resp = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code in (200, 201)
