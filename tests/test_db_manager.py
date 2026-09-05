import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.database.db_manager import DBManager


class TestDBManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_events.db")
        # Reset singleton instance for isolated test
        DBManager._instance = None
        self.db_mgr = DBManager(db_path=self.db_path)

    def tearDown(self):
        import shutil
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_log_guardian_event_and_resolve(self):
        event_id = self.db_mgr.log_guardian_event(
            file_path="C:\\Temp\\test.exe",
            detector="threat_sentinel",
            reason="Unknown executable",
            severity="HIGH",
            risk_score=75,
            signals=[{"points": 25, "reason": "Test"}]
        )
        self.assertIsInstance(event_id, int)

        events = self.db_mgr.get_recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "pending")

        self.db_mgr.resolve_guardian_event(event_id, "quarantined")
        updated_events = self.db_mgr.get_recent_events(limit=10)
        self.assertEqual(updated_events[0]["status"], "quarantined")

    def test_log_process_event_and_anomaly(self):
        proc_id = self.db_mgr.log_process_event(
            event_type="started",
            pid=1234,
            name="cmd.exe",
            parent_pid=5678,
            parent_name="winword.exe",
            anomaly_flag=1
        )
        self.assertIsInstance(proc_id, int)

        anomaly_id = self.db_mgr.log_anomaly(
            source="process",
            entity_name="cmd.exe",
            anomaly_type="suspicious_spawn",
            score=80.0,
            description="Office spawned cmd"
        )
        self.assertIsInstance(anomaly_id, int)

    def test_get_away_summary(self):
        # Insert sample events
        self.db_mgr.log_cleanup_event(files_removed=10, dirs_removed=2, space_recovered_mb=120.5, dry_run=False)
        self.db_mgr.log_guardian_event("C:\\test\\a.exe", "threat_sentinel", "Disguised", "HIGH")
        self.db_mgr.log_anomaly("system", "CPU", "cpu_burst", 95.0, "CPU Spike")

        summary = self.db_mgr.get_away_summary(window_hours=1)
        self.assertEqual(summary["cleanups_count"], 1)
        self.assertEqual(summary["space_recovered_mb"], 120.5)
        self.assertEqual(summary["suspicious_count"], 1)
        self.assertEqual(summary["anomalies_count"], 1)
        self.assertIn("Attention recommended", summary["status_assessment"])


if __name__ == "__main__":
    unittest.main()
