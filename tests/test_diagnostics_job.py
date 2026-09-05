import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.actions.diagnostics_job import DiagnosticsJob
from src.database.db_manager import DBManager


class TestDiagnosticsJob(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "diag_test.db")
        self.db_mgr = DBManager(db_path=self.db_path)
        self.config = {
            "watch_folders": [self.tmpdir]
        }
        self.diag = DiagnosticsJob(config=self.config, db_mgr=self.db_mgr)

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_diagnostics_run_all_checks(self):
        results = self.diag.run_all_checks()

        self.assertIn(results["overall_status"], ["PASS", "WARN"])
        self.assertGreaterEqual(results["passed_count"], 3)
        self.assertGreaterEqual(results["total_checks"], 4)
        self.assertGreaterEqual(results["duration_ms"], 0)
        self.assertTrue(len(results["checks"]) >= 4)

        check_names = [c["name"] for c in results["checks"]]
        self.assertIn("SQLite Database Integrity", check_names)
        self.assertIn("Watch Folders Accessibility", check_names)
        self.assertIn("System Telemetry Sensors", check_names)

    def test_diagnostics_format_report(self):
        results = self.diag.run_all_checks()
        report = self.diag.format_report(results)

        self.assertIsInstance(report, str)
        self.assertIn("GHOST OS DIAGNOSTICS REPORT", report)
        self.assertIn("SQLite Database Integrity", report)

    def test_diagnostics_states_and_repeatability(self):
        # Run #1
        r1 = self.diag.run_all_checks()
        self.assertEqual(self.diag.state, "COMPLETED")
        self.assertIn(r1["overall_status"], ["PASS", "WARN"])

        # Run #2
        r2 = self.diag.run_all_checks()
        self.assertEqual(self.diag.state, "COMPLETED")
        self.assertIn(r2["overall_status"], ["PASS", "WARN"])


if __name__ == "__main__":
    unittest.main()
