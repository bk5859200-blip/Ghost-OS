import os
import sys
import time
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.actions.scan_job import ManualScanJob
from src.intelligence.threat_sentinel import ThreatSentinel
from src.decision.decision_engine import DecisionEngine, ASK_USER, NOTIFY
from src.decision.safety_engine import SafetyEngine
from src.database.db_manager import DBManager
from src.core.ghost_core import GhostCore


class TestScanJob(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.watch_dir1 = os.path.join(self.tmpdir, "watch1")
        self.watch_dir2 = os.path.join(self.tmpdir, "watch2")
        os.makedirs(self.watch_dir1, exist_ok=True)
        os.makedirs(self.watch_dir2, exist_ok=True)

        self.db_path = os.path.join(self.tmpdir, "scan_test.db")
        self.db_mgr = DBManager(db_path=self.db_path)
        self.sentinel = ThreatSentinel()
        self.decision_engine = DecisionEngine()

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_scan_job_lifecycle_and_progress(self):
        # Create benign and suspicious files in watch folders
        f1 = os.path.join(self.watch_dir1, "benign_doc.txt")
        with open(f1, "w") as f:
            f.write("Hello world plain text")

        f2 = os.path.join(self.watch_dir1, "report.pdf.exe")
        with open(f2, "w") as f:
            f.write("MZ fake executable header payload")

        f3 = os.path.join(self.watch_dir2, "setup.vbs")
        with open(f3, "w") as f:
            f.write("WScript.CreateObject('WScript.Shell')")

        progress_calls = []
        completed_results = []

        def on_progress(current, total, file_path):
            progress_calls.append((current, total, file_path))

        def on_complete(result):
            completed_results.append(result)

        job = ManualScanJob(
            watch_folders=[self.watch_dir1, self.watch_dir2],
            threat_sentinel=self.sentinel,
            on_progress=on_progress,
            on_complete=on_complete
        )

        started = job.start()
        self.assertTrue(started)
        job.join(timeout=10.0)

        self.assertFalse(job.is_running)
        self.assertTrue(job.completed)
        self.assertEqual(job.total_files, 3)
        self.assertEqual(job.scanned_count, 3)
        self.assertEqual(job.progress_pct, 100.0)
        self.assertTrue(len(progress_calls) >= 3)
        self.assertEqual(len(completed_results), 1)

        result = completed_results[0]
        self.assertEqual(result["total_files"], 3)
        self.assertTrue(result["flagged_count"] >= 1)  # report.pdf.exe and/or setup.vbs flagged

    def test_scan_job_cancellation(self):
        # Create many files
        for i in range(20):
            with open(os.path.join(self.watch_dir1, f"file_{i}.txt"), "w") as f:
                f.write(f"Sample data {i}")

        job = ManualScanJob(
            watch_folders=[self.watch_dir1],
            threat_sentinel=self.sentinel
        )
        job.start()
        time.sleep(0.01)
        job.cancel()
        job.join(timeout=5.0)

        self.assertFalse(job.is_running)
        self.assertIn(job.state, ["CANCELLED", "COMPLETED"])

    def test_scan_job_double_start_prevention(self):
        for i in range(10):
            with open(os.path.join(self.watch_dir1, f"file_{i}.txt"), "w") as f:
                f.write(f"Sample data {i}")

        job = ManualScanJob(
            watch_folders=[self.watch_dir1],
            threat_sentinel=self.sentinel
        )
        first_start = job.start()
        second_start = job.start()
        self.assertTrue(first_start)
        self.assertFalse(second_start)
        job.join(timeout=5.0)

    def test_scan_job_sequential_re_runnable(self):
        with open(os.path.join(self.watch_dir1, "test.txt"), "w") as f:
            f.write("Sample")

        job1 = ManualScanJob(watch_folders=[self.watch_dir1], threat_sentinel=self.sentinel)
        job1.start()
        job1.join(timeout=5.0)
        self.assertEqual(job1.state, "COMPLETED")

        job2 = ManualScanJob(watch_folders=[self.watch_dir1], threat_sentinel=self.sentinel)
        job2.start()
        job2.join(timeout=5.0)
        self.assertEqual(job2.state, "COMPLETED")

    def test_disguised_file_flagging_consistency_between_scan_and_background_watcher(self):
        """
        Regression test: Ensures disguised double-extension files (e.g. invoice.pdf.exe)
        are flagged consistently by BOTH ManualScanJob and the background file event pipeline.
        """
        disguised_path = os.path.join(self.watch_dir1, "invoice.pdf.exe")
        with open(disguised_path, "w") as f:
            f.write("MZ fake executable header payload")

        # 1. Run through ManualScanJob
        scan_job = ManualScanJob(
            watch_folders=[self.watch_dir1],
            threat_sentinel=self.sentinel,
            decision_engine=self.decision_engine
        )
        scan_job.start()
        scan_job.join(timeout=5.0)

        self.assertEqual(scan_job.state, "COMPLETED")
        self.assertEqual(len(scan_job.flagged_items), 1)
        self.assertEqual(scan_job.flagged_items[0]["file_path"], disguised_path)
        scan_outcome = scan_job.flagged_items[0]["outcome"]
        self.assertIn(scan_outcome, [ASK_USER, NOTIFY])

        # 2. Run through background pipeline (GhostCore.execute_event_pipeline)
        config = {
            "monitoring": {"poll_interval_seconds": 1, "telemetry_retention_days": 1},
            "thresholds": {"cpu": {"critical_percent": 90}},
            "watch_folders": [self.watch_dir1],
            "security": {"protected_processes": [], "protected_paths": []},
            "cleanup": {"stale_temp_age_hours": 24},
            "notifications": {"cooldown_seconds": 120, "aggregation_window_seconds": 300},
            "safety": {"dry_run": True}
        }
        core = GhostCore(config=config, db_mgr=self.db_mgr)
        pipeline_res = core.execute_event_pipeline(disguised_path)

        self.assertEqual(pipeline_res["status"], "processed")
        self.assertEqual(pipeline_res["outcome"], scan_outcome)


if __name__ == "__main__":
    unittest.main()
