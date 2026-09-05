import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.ghost_core import GhostCore
from src.database.db_manager import DBManager


class TestIntegrationPipeline(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.watch_dir = os.path.join(self.tmpdir, "watch")
        self.clean_dir = os.path.join(self.tmpdir, "clean")
        os.makedirs(self.watch_dir, exist_ok=True)
        os.makedirs(self.clean_dir, exist_ok=True)

        self.db_path = os.path.join(self.tmpdir, "integration.db")
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)

        self.config = {
            "ghost": {"startup": False},
            "monitoring": {
                "system_interval_seconds": 1,
                "process_interval_seconds": 2,
                "db_cleanup_days": 7
            },
            "thresholds": {
                "cpu": {"critical_percent": 90, "consecutive_ticks": 3},
                "memory": {"critical_percent": 95},
                "disk": {"warning_percent": 90}
            },
            "notifications": {
                "enabled": True,
                "cooldown_seconds": 0,
                "aggregate_window_seconds": 300
            },
            "watch_folders": [self.watch_dir],
            "cleanup": {
                "enabled": True,
                "require_confirmation": True,
                "stale_installer_days": 30,
                "stale_temp_days": 14
            },
            "security": {
                "protected_processes": ["explorer.exe"],
                "protected_paths": ["C:\\Windows"]
            },
            "automation": {
                "enabled": True,
                "auto_trim_memory": False,
                "auto_lower_priority": False
            },
            "safety": {"dry_run": True}
        }
        self.core = GhostCore(self.config, db_mgr=self.db_mgr)
        self.core.notifier.toaster = None  # Mock headless mode

    def tearDown(self):
        import shutil
        self.core.stop()
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_file_arrival_to_sentinel_to_notification(self):
        # Create a disguised executable in watch folder
        test_file = os.path.join(self.watch_dir, "invoice.pdf.exe")
        with open(test_file, "wb") as f:
            f.write(b"MZfakeexecutablepayload")

        result = self.core.execute_event_pipeline(test_file)
        self.assertEqual(result["status"], "processed")
        self.assertIn(result["severity"], ["HIGH", "CRITICAL", "MEDIUM"])

        # Verify recorded in DB
        events = self.db_mgr.get_recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["file_path"], os.path.normpath(test_file))

        # Verify notification logged in DB
        conn = self.db_mgr.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notifications")
        notifs = cursor.fetchall()
        conn.close()
        self.assertGreaterEqual(len(notifs), 1)

    def test_cleaner_preview_to_dry_run_to_db(self):
        # Create candidate temporary files in isolated clean_dir
        temp_file = os.path.join(self.clean_dir, "junk.tmp")
        with open(temp_file, "wb") as f:
            f.write(b"temporary data" * 100)

        self.core.cleaner.disposable_roots = [self.clean_dir]
        preview = self.core.cleaner.preview()
        self.assertEqual(preview["count"], 1)

        result = self.core.cleaner.execute(preview["candidates"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["files_removed"], 0)
        self.assertTrue(os.path.exists(temp_file))  # Dry run leaves file intact

        # Verify cleanup event logged
        conn = self.db_mgr.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cleanup_events")
        cleanups = cursor.fetchall()
        conn.close()
        self.assertEqual(len(cleanups), 1)
        self.assertEqual(cleanups[0]["dry_run"], 1)

    def test_quarantine_to_restore_to_db_verification(self):
        test_file = os.path.join(self.watch_dir, "bad_payload.exe")
        with open(test_file, "wb") as f:
            f.write(b"sample suspicious payload")

        event_id = self.db_mgr.log_guardian_event(test_file, "threat_sentinel", "Suspicious file", "HIGH")
        success, q_path, file_hash = self.core.quarantine.quarantine_file(event_id, test_file)

        self.assertTrue(success)
        self.assertFalse(os.path.exists(test_file))
        self.assertTrue(os.path.exists(q_path))

        # Restore
        restored = self.core.quarantine.restore_file(q_path, test_file)
        self.assertTrue(restored)
        self.assertTrue(os.path.exists(test_file))
        self.assertFalse(os.path.exists(q_path))


if __name__ == "__main__":
    unittest.main()
