import pytest
import io
from server.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_check(client):
    resp = client.get('/health')
    assert resp.status_code == 200

def test_upload_flow(client):
    data = {'file': (io.BytesIO(b"test data"), 'test.enc')}
    resp = client.post('/upload', data=data, content_type='multipart/form-data')
    assert resp.status_code == 201
