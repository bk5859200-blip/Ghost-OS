import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.ghost_core import GhostCore, STATE_STARTING, STATE_NORMAL, STATE_WATCHING
from src.database.db_manager import DBManager


class TestGhostCore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "core_test.db")
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
                "enabled": False,
                "cooldown_seconds": 120,
                "aggregate_window_seconds": 300
            },
            "watch_folders": [self.tmpdir],
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

    def tearDown(self):
        import shutil
        self.core.stop()
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_core_lifecycle_and_states(self):
        self.assertEqual(self.core.get_health_state(), STATE_STARTING)
        self.core.start()
        self.assertTrue(self.core.running)
        self.assertEqual(self.core.get_health_state(), STATE_WATCHING)

        self.core.pause()
        self.assertFalse(self.core.running)

        self.core.resume()
        self.assertTrue(self.core.running)
        self.assertEqual(self.core.get_health_state(), STATE_WATCHING)

        self.core.stop()
        self.assertFalse(self.core.running)
        self.assertEqual(self.core.get_health_state(), STATE_NORMAL)

    def test_quick_scan_on_clean_dir(self):
        f = os.path.join(self.tmpdir, "readme.txt")
        with open(f, "w", encoding="utf-8") as file:
            file.write("sample notes")

        self.core.run_quick_scan()
        events = self.core.db_mgr.get_recent_events(limit=10)
        self.assertEqual(len(events), 0)

    def test_away_summary(self):
        summary = self.core.get_away_summary(window_hours=1)
        self.assertIn("cleanups_count", summary)
        self.assertIn("space_recovered_mb", summary)
        self.assertIn("status_assessment", summary)


if __name__ == "__main__":
    unittest.main()
