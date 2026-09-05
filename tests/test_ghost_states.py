import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.ghost_core import (
    GhostCore, STATE_STARTING, STATE_NORMAL, STATE_WATCHING,
    STATE_ATTENTION, STATE_PROTECTING, STATE_PAUSED, STATE_ERROR, STATE_STOPPING
)
from src.database.db_manager import DBManager


class TestGhostStates(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "states.db")
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)
        self.config = {
            "ghost": {"startup": False},
            "monitoring": {"system_interval_seconds": 1, "process_interval_seconds": 2, "db_cleanup_days": 7},
            "thresholds": {"cpu": {"critical_percent": 90, "consecutive_ticks": 3}, "memory": {"critical_percent": 95}, "disk": {"warning_percent": 90}},
            "notifications": {"enabled": False, "cooldown_seconds": 120, "aggregate_window_seconds": 300},
            "watch_folders": [self.tmpdir],
            "cleanup": {"enabled": True, "require_confirmation": True, "stale_installer_days": 30, "stale_temp_days": 14},
            "security": {"protected_processes": ["explorer.exe"], "protected_paths": ["C:\\Windows"]},
            "automation": {"enabled": True, "auto_trim_memory": False, "auto_lower_priority": False},
            "safety": {"dry_run": True}
        }
        self.core = GhostCore(self.config, db_mgr=self.db_mgr)

    def tearDown(self):
        import shutil
        self.core.stop()
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_state_transitions(self):
        # 1. Initial State
        self.assertEqual(self.core.get_health_state(), STATE_STARTING)

        # 2. Start State
        self.core.start()
        self.assertEqual(self.core.get_health_state(), STATE_WATCHING)

        # 3. Pause State
        self.core.pause()
        self.assertEqual(self.core.get_health_state(), STATE_PAUSED)

        # 4. Resume State
        self.core.resume()
        self.assertEqual(self.core.get_health_state(), STATE_WATCHING)

        # 5. Stop State
        self.core.stop()
        self.assertEqual(self.core.get_health_state(), STATE_NORMAL)

    def test_manual_state_setting(self):
        self.core.set_health_state(STATE_ATTENTION)
        self.assertEqual(self.core.get_health_state(), STATE_ATTENTION)

        self.core.set_health_state(STATE_PROTECTING)
        self.assertEqual(self.core.get_health_state(), STATE_PROTECTING)


if __name__ == "__main__":
    unittest.main()
