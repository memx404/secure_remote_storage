"""
Test Suite for Network Module
=============================
Uses 'requests_mock' to simulate server responses.
This allows us to test client logic (success/fail handling)
without running a real Flask server.
"""

import os
import pytest
import requests_mock
from src import network

# Mock Server URL (Must match src/network.py)
BASE_URL = "http://127.0.0.1:5000"

def test_check_health_success():
    """Verify check_server_health returns True on 200 OK."""
    with requests_mock.Mocker() as m:
        # Fake a 200 OK response from /health
        m.get(f"{BASE_URL}/health", status_code=200)
        assert network.check_server_health() is True

def test_check_health_failure():
    """Verify check_server_health returns False on 500 Error."""
    with requests_mock.Mocker() as m:
        # Fake a 500 Server Error
        m.get(f"{BASE_URL}/health", status_code=500)
        assert network.check_server_health() is False

def test_upload_success(tmp_path):
    """Verify upload_file handles 201 Created correctly."""
    # Create a dummy file to upload
    dummy_file = tmp_path / "test.txt"
    dummy_file.write_text("Hello World")
    
    with requests_mock.Mocker() as m:
        # Fake a successful upload response
        m.post(f"{BASE_URL}/upload", status_code=201)
        
        result = network.upload_file(str(dummy_file))
        assert result is True

def test_download_success(tmp_path):
    """Verify download_file saves content correctly."""
    with requests_mock.Mocker() as m:
        # Fake the file content coming from the server
        fake_content = b"Downloaded Data"
        m.get(f"{BASE_URL}/download/test.txt", content=fake_content, status_code=200)
        
        # Download to the temp directory
        saved_path = network.download_file("test.txt", str(tmp_path))
        
        # Check if file exists and has correct content
        assert os.path.exists(saved_path)
        with open(saved_path, "rb") as f:
            assert f.read() == fake_content
