import unittest
import os
import shutil
from unittest.mock import patch, MagicMock
from src import network

class TestNetwork(unittest.TestCase):

    def setUp(self):
        """
        Run BEFORE every test. 
        Creates a dummy certificate file so the 'Defensive Check' passes.
        """
        self.cert_dir = "nginx/certs"
        self.cert_path = os.path.join(self.cert_dir, "server.crt")
        
        # Ensure directory exists
        os.makedirs(self.cert_dir, exist_ok=True)
        
        # Create a dummy file (content doesn't matter because we mock requests)
        with open(self.cert_path, 'w') as f:
            f.write("DUMMY CERTIFICATE")

    def tearDown(self):
        """
        Run AFTER every test.
        Cleans up the dummy file to leave the system clean.
        """
        if os.path.exists(self.cert_path):
            os.remove(self.cert_path)
        # Try to remove the directory if it's empty
        try:
            os.rmdir(self.cert_dir)
        except OSError:
            pass

    @patch('src.network.requests.get')
    def test_check_health_success(self, mock_get):
        """Test that server returns True when status is 200"""
        # The file exists (thanks to setUp), so the code proceeds to network call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = network.check_server_status()
        self.assertTrue(result)

    @patch('src.network.requests.get')
    def test_check_health_failure(self, mock_get):
        """Test that server returns False when status is 500"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = network.check_server_status()
        self.assertFalse(result)

    @patch('src.network.requests.post')
    def test_upload_success(self, mock_post):
        """Test successful file upload"""
        mock_response = MagicMock()
        mock_response.status_code = 201 
        mock_post.return_value = mock_response

        result = network.upload_file("test.txt", b"dummy_encrypted_data")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 201)

    @patch('src.network.requests.get')
    def test_download_success(self, mock_get):
        """Test successful file download"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"encrypted_content"
        mock_get.return_value = mock_response

        result = network.download_file("test.txt")
        
        self.assertEqual(result, b"encrypted_content")

if __name__ == '__main__':
    unittest.main()
