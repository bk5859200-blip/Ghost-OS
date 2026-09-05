import os
import sys
import time
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.actions.scan_job import ManualScanJob
from src.intelligence.threat_sentinel import ThreatSentinel
from src.decision.decision_engine import DecisionEngine
from src.decision.safety_engine import SafetyEngine
from src.database.db_manager import DBManager


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


if __name__ == "__main__":
    unittest.main()
