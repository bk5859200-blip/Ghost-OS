import os
import sys
import tempfile
import unittest
import tkinter as tk

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.ghost_core import GhostCore
from src.database.db_manager import DBManager
from src.ui.control_center import ControlCenterApp, ControlCenterManager


class TestControlCenterUI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "ui_test.db")
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
        self.db_mgr.close()
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_control_center_app_instantiation_and_tabs(self):
        # Create Tk app headless
        app = ControlCenterApp(self.core, initial_tab="overview")
        self.assertIsNotNone(app.root)

        # Test tab switching
        app._select_tab("scan")
        self.assertEqual(app.notebook.tab(app.notebook.select(), "text").strip(), "Quick Scan")

        app._select_tab("quarantine")
        self.assertEqual(app.notebook.tab(app.notebook.select(), "text").strip(), "Quarantine")

        app._select_tab("activity")
        self.assertEqual(app.notebook.tab(app.notebook.select(), "text").strip(), "Activity History")

        app._select_tab("settings")
        self.assertEqual(app.notebook.tab(app.notebook.select(), "text").strip(), "Policy Settings")

        app._select_tab("diagnostics")
        self.assertEqual(app.notebook.tab(app.notebook.select(), "text").strip(), "Diagnostics")

        # Cleanup
        app.root.destroy()

    def test_control_center_manager_instantiation(self):
        mgr = ControlCenterManager(self.core)
        self.assertIsNotNone(mgr)
        self.assertIsNone(mgr._app)


if __name__ == "__main__":
    unittest.main()
