import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.actions.quarantine_manager import QuarantineManager
from src.database.db_manager import DBManager


class TestQuarantineManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.quarantine_dir = os.path.join(self.tmpdir, "quarantine")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)
        self.qm = QuarantineManager(quarantine_dir=self.quarantine_dir, db_mgr=self.db_mgr)

    def tearDown(self):
        import shutil
        self.db_mgr.close()
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_quarantine_and_restore(self):
        import hashlib
        # Create a sample file
        orig_file = os.path.join(self.tmpdir, "malicious_script.vbs")
        test_payload = b"WScript.Echo 'Ghost OS Security Test 12345'\r\nDo While True: Loop"
        with open(orig_file, "wb") as f:
            f.write(test_payload)

        expected_hash = hashlib.sha256(test_payload).hexdigest()

        event_id = self.db_mgr.log_guardian_event(orig_file, "threat_sentinel", "Suspicious script", "HIGH")
        success, q_path, file_hash = self.qm.quarantine_file(event_id, orig_file)

        self.assertTrue(success)
        self.assertIsNotNone(q_path)
        self.assertEqual(file_hash, expected_hash)
        self.assertFalse(os.path.exists(orig_file))
        self.assertTrue(os.path.exists(q_path))

        # Restore file
        restore_success = self.qm.restore_file(q_path, orig_file)
        self.assertTrue(restore_success)
        self.assertTrue(os.path.exists(orig_file))
        self.assertFalse(os.path.exists(q_path))

        # Verify content and SHA-256 integrity after restore
        with open(orig_file, "rb") as f:
            restored_content = f.read()
        self.assertEqual(restored_content, test_payload)
        restored_hash = hashlib.sha256(restored_content).hexdigest()
        self.assertEqual(restored_hash, expected_hash)

    def test_quarantine_nonexistent_fails_gracefully(self):
        success, q_path, _ = self.qm.quarantine_file(999, os.path.join(self.tmpdir, "ghost_missing.exe"))
        self.assertFalse(success)
        self.assertIsNone(q_path)


if __name__ == "__main__":
    unittest.main()
