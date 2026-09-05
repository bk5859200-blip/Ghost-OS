import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.intelligence.threat_sentinel import ThreatSentinel


class MockDefenderScanner:
    def __init__(self, should_flag=False):
        self.available = True
        self.should_flag = should_flag

    def scan_file(self, file_path):
        return {
            "scanned": True,
            "threat_found": self.should_flag,
            "detail": "Mock malware detected" if self.should_flag else "Clean"
        }


class TestThreatSentinel(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sentinel = ThreatSentinel(config={}, defender_scanner=MockDefenderScanner(should_flag=False))

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_file(self, filename, content=b"test data"):
        path = os.path.join(self.tmpdir, filename)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_analyze_clean_file(self):
        path = self._create_file("document.txt")
        report = self.sentinel.analyze_file(path)
        self.assertIsNotNone(report)
        self.assertEqual(report["classification"], "LOW")
        self.assertEqual(report["risk_score"], 0)

    def test_analyze_suspicious_double_extension(self):
        path = self._create_file("invoice.pdf.exe")
        report = self.sentinel.analyze_file(path)
        self.assertIsNotNone(report)
        self.assertGreaterEqual(report["risk_score"], 30)
        self.assertIn("invoice.pdf.exe", report["explanation"])

    def test_analyze_with_defender_confirmed_malware(self):
        malware_sentinel = ThreatSentinel(config={}, defender_scanner=MockDefenderScanner(should_flag=True))
        path = self._create_file("bad_installer.exe")
        report = malware_sentinel.analyze_file(path)
        self.assertIsNotNone(report)
        self.assertEqual(report["classification"], "CRITICAL")
        self.assertEqual(report["risk_score"], 100)
        self.assertTrue(report["threat_confirmed"])
        self.assertEqual(report["category"], "malware_confirmed")

    def test_nonexistent_file_returns_none(self):
        report = self.sentinel.analyze_file(os.path.join(self.tmpdir, "missing.bin"))
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
