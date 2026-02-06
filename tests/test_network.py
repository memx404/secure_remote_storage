import unittest
from unittest.mock import patch, MagicMock
from src import network

class TestNetwork(unittest.TestCase):

    # --- FIX: Patch 'os.path.exists' GLOBALLY to always return True ---
    # This tricks the "Defensive Check" without needing real files.
    @patch('os.path.exists', return_value=True)
    @patch('src.network.requests.get')
    def test_check_health_success(self, mock_get, mock_exists):
        """Test that server returns True when status is 200"""
        
        # 1. Setup the Network Mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # 2. Run the code
        # Note: os.path.exists() returns True automatically now!
        result = network.check_server_status()
        
        # 3. Verify
        self.assertTrue(result)

    @patch('os.path.exists', return_value=True)
    @patch('src.network.requests.get')
    def test_check_health_failure(self, mock_get, mock_exists):
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
