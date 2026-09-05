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


class TestLongRunningStability(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "stability.db")
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)
        self.config = {
            "ghost": {"startup": False},
            "monitoring": {"system_interval_seconds": 0.05, "process_interval_seconds": 0.1, "db_cleanup_days": 7},
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

    def test_multi_cycle_continuous_monitoring_stability(self):
        proc = psutil.Process()
        self.core.start()
        time.sleep(0.2)

        start_thread_count = threading.active_count()
        start_mem_mb = proc.memory_info().rss / (1024 * 1024)

        # Simulate 100 rapid telemetry inserts and process cycles
        for i in range(100):
            self.db_mgr.insert_system_metrics(
                cpu=25.0 + (i % 10),
                ram=50.0,
                disk_pct=60.0,
                disk_read=1.0,
                disk_write=2.0,
                net_sent=0.5,
                net_recv=0.8
            )
            if i % 10 == 0:
                self.core._log_self_performance()
            time.sleep(0.01)

        self.db_mgr.flush()

        end_thread_count = threading.active_count()
        end_mem_mb = proc.memory_info().rss / (1024 * 1024)
        mem_diff_mb = end_mem_mb - start_mem_mb

        # Thread count should remain unchanged
        self.assertLessEqual(end_thread_count - start_thread_count, 2, "Thread count should not leak across cycles")

        # Memory diff should be minimal
        self.assertLess(mem_diff_mb, 40.0, f"Memory should not leak significantly (growth: {mem_diff_mb:.1f} MB)")

        # Verify DB integrity
        conn = self.db_mgr.get_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        self.assertEqual(cursor.fetchone()[0], "ok")

        cursor.execute("SELECT COUNT(*) FROM system_metrics;")
        self.assertGreaterEqual(cursor.fetchone()[0], 100)


if __name__ == "__main__":
    unittest.main()
