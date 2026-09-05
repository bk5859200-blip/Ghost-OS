import os
import sys
import time
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.intelligence.rule_engine import RuleEngine


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = {"cleanup": {"stale_installer_days": 30, "stale_temp_days": 14}}
        self.engine = RuleEngine(self.config)

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _touch(self, name, age_days=0, size=10):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(b"x" * size)
        if age_days:
            old_time = time.time() - age_days * 86400
            os.utime(path, (old_time, old_time))
        return path

    def test_disguised_extension_flagged(self):
        path = self._touch("invoice.pdf.exe")
        result = self.engine.evaluate(path)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["score"], 30)
        self.assertEqual(result["category"], "suspicious")
        self.assertTrue(any("Disguised" in s.reason for s in result["signals"]))

    def test_clean_recent_text_not_flagged(self):
        path = self._touch("notes.txt")
        result = self.engine.evaluate(path)
        self.assertIsNone(result)

    def test_stale_temp_file_flagged_junk(self):
        path = self._touch("cache.tmp", age_days=20)
        result = self.engine.evaluate(path)
        self.assertIsNotNone(result)
        self.assertEqual(result["category"], "junk")
        self.assertEqual(result["classification"], "LOW")

    def test_nonexistent_file_returns_none(self):
        result = self.engine.evaluate(os.path.join(self.tmpdir, "ghost.exe"))
        self.assertIsNone(result)

    def test_empty_stale_file_flagged(self):
        path = self._touch("leftover.dat", age_days=5, size=0)
        result = self.engine.evaluate(path)
        self.assertIsNotNone(result)

    def test_script_in_unusual_location(self):
        path = self._touch("payload.vbs")
        result = self.engine.evaluate(path)
        self.assertIsNotNone(result)
        self.assertTrue(any("Script file" in s.reason for s in result["signals"]))

    def test_sha256_computation(self):
        path = self._touch("sample.bin", size=100)
        sha = self.engine.calculate_sha256(path)
        self.assertIsNotNone(sha)
        self.assertEqual(len(sha), 64)

    def test_explanation_formatting(self):
        path = self._touch("statement.doc.exe")
        result = self.engine.evaluate(path)
        explanation = self.engine.format_explanation(result)
        self.assertIn("Risk Score:", explanation)
        self.assertIn("Signals:", explanation)
        self.assertIn("Classification:", explanation)


if __name__ == "__main__":
    unittest.main()
