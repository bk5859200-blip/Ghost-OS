import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.processes.process_monitor import ProcessMonitor


class TestProcessMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ProcessMonitor()

    def test_record_profile_and_history(self):
        proc = {
            "pid": 9999,
            "name": "calc.exe",
            "cpu_percent": 12.5,
            "memory_rss_mb": 45.0
        }
        self.monitor.record_process_start(proc)
        profile = self.monitor.get_profile("calc.exe")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["executions"], 1)
        self.assertEqual(profile["avg_cpu_percent"], 12.5)

    def test_check_benign_spawn(self):
        proc = {
            "pid": 1001,
            "name": "notepad.exe",
            "parent_name": "explorer.exe"
        }
        is_suspicious, reason = self.monitor.check_spawn_anomaly(proc)
        self.assertFalse(is_suspicious)
        self.assertIsNone(reason)

    def test_check_suspicious_document_spawn(self):
        proc = {
            "pid": 1002,
            "name": "powershell.exe",
            "parent_name": "winword.exe"
        }
        is_suspicious, reason = self.monitor.check_spawn_anomaly(proc)
        self.assertTrue(is_suspicious)
        self.assertIn("Suspicious child process", reason)


if __name__ == "__main__":
    unittest.main()
