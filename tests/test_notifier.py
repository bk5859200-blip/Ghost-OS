import os
import sys
import time
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.notifications.notifier import Notifier
from src.database.db_manager import DBManager


class TestNotifier(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "notif_test.db")
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)
        # Instantiate Notifier without interactive GUI toast dependency
        self.notifier = Notifier(
            app_name="GhostOSTest",
            cooldown_seconds=2,
            aggregate_window_seconds=10,
            enabled=True,
            db_mgr=self.db_mgr
        )
        self.notifier.toaster = None  # Mock headless mode

    def tearDown(self):
        import shutil
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_cooldown_suppression(self):
        # First notification should send
        send1, supp1 = self.notifier._should_send("test:signal")
        self.assertTrue(send1)
        self.assertEqual(supp1, 0)

        # Immediate second notification should be suppressed
        send2, supp2 = self.notifier._should_send("test:signal")
        self.assertFalse(send2)
        self.assertEqual(supp2, 1)

        # Third notification within cooldown should increment count
        send3, supp3 = self.notifier._should_send("test:signal")
        self.assertFalse(send3)
        self.assertEqual(supp3, 2)

        # Wait for cooldown to expire
        time.sleep(2.1)
        send4, supp4 = self.notifier._should_send("test:signal")
        self.assertTrue(send4)
        self.assertEqual(supp4, 2)

    def test_notification_recorded_in_db(self):
        self.notifier.notify_info("Test Title", "Test Message", signal_key="custom_key")
        conn = self.db_mgr.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notifications WHERE signal_key = 'custom_key'")
        rows = cursor.fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "Test Title")


if __name__ == "__main__":
    unittest.main()
