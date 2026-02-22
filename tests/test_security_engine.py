import unittest
import shutil
import os
from src.security.hsm import HSM
from src.security.signer import Signer

TEST_DIR = "test_srs_keystore"

class TestSecurityEngine(unittest.TestCase):
    def setUp(self):
        os.makedirs(TEST_DIR, exist_ok=True)

    def tearDown(self):
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)

    def test_full_security_flow(self):
        print("\n[TEST] Generating Identity...")
        # 1. Generate Keys
        HSM.generate_identity("test_user", "pass", TEST_DIR)
        
        print("[TEST] Signing Data...")
        data = b"Confidential SRS Data"
        # 2. Sign Data
        sig = Signer.sign_data(data, "test_user", "pass", TEST_DIR)
        
        print("[TEST] Verifying Signature...")
        # 3. Verify Signature
        is_valid = Signer.verify_signature(data, sig, "test_user", "pass", TEST_DIR)
        self.assertTrue(is_valid)
        print("[SUCCESS] Security Engine is Operational.")

if __name__ == "__main__":
    unittest.main()
