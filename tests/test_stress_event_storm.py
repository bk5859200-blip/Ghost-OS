import os
import sys
import time
import tempfile
import threading
import psutil
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.ghost_core import GhostCore
from src.database.db_manager import DBManager
from src.watchers.file_watcher import _GhostEventHandler


class TestStressEventStorm(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "stress.db")
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

    def test_500_event_file_storm_bounded_threads(self):
        self.core.start()
        time.sleep(0.3)

        initial_thread_count = threading.active_count()
        proc = psutil.Process()
        initial_mem_mb = proc.memory_info().rss / (1024 * 1024)

        processed_count = 0
        lock = threading.Lock()

        def on_event(path):
            nonlocal processed_count
            with lock:
                processed_count += 1
            self.core.execute_event_pipeline(path)

        handler = _GhostEventHandler(on_file_event=on_event, debounce_seconds=0.05)

        class MockEvent:
            def __init__(self, p):
                self.src_path = p
                self.is_directory = False

        # Fire 500 events rapidly
        for i in range(500):
            test_path = os.path.join(self.tmpdir, f"file_{i}.bat")
            # Write every 10th file to disk
            if i % 10 == 0:
                with open(test_path, "w") as f:
                    f.write("echo test")
            handler.on_created(MockEvent(test_path))

        # Check that thread count is strictly bounded during storm
        current_threads = threading.active_count()
        self.assertLess(current_threads, 25, f"Thread count during storm ({current_threads}) must not explode")

        # Allow worker pool to drain
        time.sleep(1.5)
        handler.stop()

        final_mem_mb = proc.memory_info().rss / (1024 * 1024)
        mem_growth_mb = final_mem_mb - initial_mem_mb

        self.assertLess(mem_growth_mb, 50.0, f"Memory growth ({mem_growth_mb:.1f} MB) must remain flat after 500 events")


if __name__ == "__main__":
    unittest.main()
