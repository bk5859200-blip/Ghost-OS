import os
import sys
import time
import tempfile
import threading
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.ghost_core import GhostCore, STATE_WATCHING, STATE_PAUSED
from src.database.db_manager import DBManager
from src.watchers.file_watcher import _GhostEventHandler
from src.intelligence.threat_sentinel import ThreatSentinel, DEFENDER_SCAN_SEMAPHORE


class TestThreadStability(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "thread_test.db")
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)
        self.config = {
            "ghost": {"startup": False},
            "monitoring": {"system_interval_seconds": 0.5, "process_interval_seconds": 1, "db_cleanup_days": 7},
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

    def test_pause_resume_thread_survival(self):
        # Start core
        self.core.start()
        time.sleep(0.5)

        initial_threads = list(self.core._threads)
        self.assertGreater(len(initial_threads), 0)
        for t in initial_threads:
            self.assertTrue(t.is_alive(), f"Thread {t.name} should be alive initially")

        # Cycle pause and resume multiple times
        for _ in range(3):
            self.core.pause()
            self.assertEqual(self.core.get_health_state(), STATE_PAUSED)
            time.sleep(0.3)
            for t in initial_threads:
                self.assertTrue(t.is_alive(), f"Thread {t.name} must survive pause")

            self.core.resume()
            self.assertEqual(self.core.get_health_state(), STATE_WATCHING)
            time.sleep(0.3)
            for t in initial_threads:
                self.assertTrue(t.is_alive(), f"Thread {t.name} must remain alive after resume")

    def test_tmp_file_exclusion_in_watcher(self):
        self.assertNotIn(".tmp", _GhostEventHandler.RELEVANT_EXTENSIONS)

        events_received = []
        handler = _GhostEventHandler(on_file_event=lambda p: events_received.append(p), debounce_seconds=0.05)

        # Simulate tmp file vs real script file
        class DummyEvent:
            def __init__(self, path, is_dir=False):
                self.src_path = path
                self.is_directory = is_dir

        tmp_path = os.path.join(self.tmpdir, "tempfile.tmp")
        with open(tmp_path, "w") as f:
            f.write("temporary data")

        ps1_path = os.path.join(self.tmpdir, "script.ps1")
        with open(ps1_path, "w") as f:
            f.write("Write-Output 'hello'")

        handler.on_created(DummyEvent(tmp_path))
        time.sleep(0.15)
        self.assertEqual(len(events_received), 0, ".tmp files must be completely ignored by file watcher")

        handler.on_created(DummyEvent(ps1_path))
        time.sleep(0.2)
        handler.stop()
        self.assertEqual(len(events_received), 1, ".ps1 script file must be processed")

    def test_defender_scan_semaphore_concurrency_limit(self):
        sentinel = ThreatSentinel()
        active_scans = 0
        max_seen_concurrent = 0
        lock = threading.Lock()

        # Wrap scan_file to measure concurrency under semaphore
        original_scan = sentinel.defender.scan_file

        def mock_scan(path):
            nonlocal active_scans, max_seen_concurrent
            with lock:
                active_scans += 1
                if active_scans > max_seen_concurrent:
                    max_seen_concurrent = active_scans
            time.sleep(0.1)
            with lock:
                active_scans -= 1
            return {"scanned": True, "infected": False}

        sentinel.defender.scan_file = mock_scan

        # Launch 6 parallel analyze requests
        test_file = os.path.join(self.tmpdir, "test.exe")
        with open(test_file, "w") as f:
            f.write("test binary")

        threads = [threading.Thread(target=lambda: sentinel.analyze_file(test_file)) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertLessEqual(max_seen_concurrent, 2, "Concurrent Defender scans must not exceed semaphore limit of 2")


if __name__ == "__main__":
    unittest.main()
