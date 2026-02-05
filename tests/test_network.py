import unittest
from unittest.mock import patch, MagicMock
from src import network

class TestNetwork(unittest.TestCase):

    @patch('src.network.os.path.exists') 
    @patch('src.network.requests.get')
    def test_check_health_success(self, mock_get, mock_exists):
        """Test that server returns True when status is 200"""
        # 1. Pretend the certificate file exists
        mock_exists.return_value = True 
        
        # 2. Mock a successful network response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # 3. Run the test
        result = network.check_server_status()
        self.assertTrue(result)

    @patch('src.network.os.path.exists') # MOCK FILE SYSTEM
    @patch('src.network.requests.get')
    def test_check_health_failure(self, mock_get, mock_exists):
        """Test that server returns False when status is 500"""
        mock_exists.return_value = True # Pretend file exists
        
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