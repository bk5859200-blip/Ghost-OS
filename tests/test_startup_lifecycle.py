import os
import sys
import tempfile
import unittest
import threading
import logging
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.single_instance import SingleInstance
from src.core.ghost_core import GhostCore, STATE_WATCHING, STATE_NORMAL
from src.database.db_manager import DBManager
from src.ui.control_center import ControlCenterApp, ControlCenterManager
from src.tray.tray_app import TrayApp


class TestStartupLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "lifecycle_test.db")
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)
        self.config = {
            "ghost": {"startup": False},
            "monitoring": {"system_interval_seconds": 1, "process_interval_seconds": 2, "db_cleanup_days": 7},
            "thresholds": {"cpu": {"critical_percent": 90, "consecutive_ticks": 3}, "memory": {"critical_percent": 95}, "disk": {"warning_percent": 90}},
            "notifications": {"enabled": False, "cooldown_seconds": 120, "aggregate_window_seconds": 300},
            "watch_folders": [self.tmpdir],
            "cleanup": {"enabled": True, "require_confirmation": True, "stale_installer_days": 30, "stale_temp_days": 14},
            "security": {"protected_processes": ["explorer.exe"], "protected_paths": [r"C:\Windows"]},
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

    def test_single_instance_prevents_duplicate_process(self):
        mutex_name = f"Local\\Test_GhostOS_Mutex_{os.getpid()}"
        guard1 = SingleInstance(mutex_name=mutex_name)
        self.assertTrue(guard1.acquire())

        if sys.platform == "win32":
            guard2 = SingleInstance(mutex_name=mutex_name)
            self.assertFalse(guard2.acquire())
            self.assertTrue(guard2.already_running)

        guard1.release()

    def test_core_starts_background_watchers(self):
        self.core.start()
        self.assertTrue(self.core.running)
        self.assertEqual(self.core.get_health_state(), STATE_WATCHING)
        self.assertTrue(len(self.core._threads) >= 2)

    def test_control_center_immediate_startup_and_single_instance(self):
        mgr = ControlCenterManager(self.core)
        mock_root = MagicMock()
        mock_root.state.return_value = "normal"
        mock_notebook = MagicMock()
        mock_notebook.select.return_value = "tab_diag"
        mock_notebook.tab.return_value = "Health"
        mock_app = MagicMock(root=mock_root, notebook=mock_notebook)
        mgr._app = mock_app

        # Window is active and visible
        self.assertIsNotNone(mgr._app.root)
        self.assertEqual(mgr._app.root.state(), "normal")

        # Duplicate show call should refocus rather than create new instances
        mgr.show("diagnostics")
        mgr._focus_tab("diagnostics")
        self.assertIn("Health", mgr._app.notebook.tab(mgr._app.notebook.select(), "text"))
        self.assertEqual(mgr._app.root.state(), "normal")

        mgr._destroy_ui()

    def test_window_close_hides_to_tray_without_stopping_core(self):
        self.core.start()
        mgr = ControlCenterManager(self.core)
        current_state = ["normal"]
        mock_root = MagicMock()
        mock_root.withdraw.side_effect = lambda: current_state.clear() or current_state.append("withdrawn")
        mock_root.deiconify.side_effect = lambda: current_state.clear() or current_state.append("normal")
        mock_root.state.side_effect = lambda: current_state[0]
        mock_notebook = MagicMock()
        mock_notebook.select.return_value = "tab_scan"
        mock_notebook.tab.return_value = "Scan"
        mock_app = MagicMock(root=mock_root, notebook=mock_notebook)
        mgr._app = mock_app

        # User closes window -> hide to tray
        mgr._on_window_close()
        self.assertEqual(mgr._app.root.state(), "withdrawn")

        # GhostCore must continue monitoring in background
        self.assertTrue(self.core.running)
        self.assertEqual(self.core.get_health_state(), STATE_WATCHING)

        # Tray reopens Control Center
        mgr.show("scan")
        mgr._focus_tab("scan")
        self.assertEqual(mgr._app.root.state(), "normal")
        self.assertIn("Scan", mgr._app.notebook.tab(mgr._app.notebook.select(), "text"))

        mgr._destroy_ui()

    def test_clean_shutdown_destroys_ui_and_stops_core(self):
        self.core.start()
        mgr = ControlCenterManager(self.core)
        mock_root = MagicMock()
        mock_app = MagicMock(root=mock_root)
        mgr._app = mock_app

        # Trigger exit
        mgr.exit_app()
        mgr._destroy_ui()
        self.assertIsNone(mgr._app)

        self.core.stop()
        self.assertFalse(self.core.running)
        self.assertEqual(self.core.get_health_state(), STATE_NORMAL)

    def test_tray_app_non_blocking_start_and_stop(self):
        mgr = ControlCenterManager(self.core)
        tray = TrayApp(self.core, control_center=mgr)

        with patch.object(tray, "run") as mock_run:
            tray.start()
            self.assertIsNotNone(tray._tray_thread)
            tray._tray_thread.join(timeout=1.0)
            self.assertTrue(mock_run.called)
            tray.stop()

    def test_ui_fatal_exception_logging(self):
        mgr = ControlCenterManager(self.core)
        with patch.object(ControlCenterApp, "__init__", side_effect=RuntimeError("Test Tk Initialization Failure")):
            with self.assertRaises(RuntimeError):
                with self.assertLogs("ghost.ui.control_center", level="CRITICAL") as cm:
                    mgr.start_main_loop()
            # Verify exception details and traceback were logged
            self.assertTrue(any("Test Tk Initialization Failure" in output for output in cm.output))
            self.assertTrue(any("Traceback" in output for output in cm.output))


if __name__ == "__main__":
    unittest.main()
