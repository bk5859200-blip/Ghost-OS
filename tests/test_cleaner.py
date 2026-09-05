import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.actions.cleaner import SystemCleaner
from src.decision.safety_engine import SafetyEngine


class TestCleaner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.safety_dry = SafetyEngine({"safety": {"dry_run": True}})
        self.safety_wet = SafetyEngine({
            "security": {
                "protected_processes": [],
                "protected_paths": []
            },
            "safety": {"dry_run": False}
        })

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_preview_scan_only(self):
        cleaner = SystemCleaner(self.safety_dry)
        cleaner.disposable_roots = [self.tmpdir]

        # Create dummy temp & cache files with noticeable size (>1MB)
        f1 = os.path.join(self.tmpdir, "test1.tmp")
        f2 = os.path.join(self.tmpdir, "crash.dmp")
        with open(f1, "wb") as f:
            f.write(b"x" * (1024 * 1024))
        with open(f2, "wb") as f:
            f.write(b"x" * (1024 * 1024))

        preview = cleaner.preview()
        self.assertEqual(preview["count"], 2)
        self.assertGreaterEqual(preview["size_mb"], 1.0)
        self.assertIn("Temporary", preview["categories"])
        self.assertIn("Crash dumps", preview["categories"])
        # Verify files were NOT deleted during preview
        self.assertTrue(os.path.exists(f1))
        self.assertTrue(os.path.exists(f2))

    def test_dry_run_execution_does_not_delete(self):
        cleaner = SystemCleaner(self.safety_dry)
        cleaner.disposable_roots = [self.tmpdir]

        f1 = os.path.join(self.tmpdir, "test1.tmp")
        with open(f1, "wb") as f:
            f.write(b"data")

        preview = cleaner.preview()
        result = cleaner.execute(preview["candidates"])

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["files_removed"], 0)
        self.assertTrue(os.path.exists(f1))

    def test_live_execution_deletes_safely(self):
        cleaner = SystemCleaner(self.safety_wet)
        cleaner.disposable_roots = [self.tmpdir]

        f1 = os.path.join(self.tmpdir, "clean_me.tmp")
        with open(f1, "wb") as f:
            f.write(b"data")

        preview = cleaner.preview()
        result = cleaner.execute(preview["candidates"])

        self.assertFalse(result["dry_run"])
        self.assertEqual(result["files_removed"], 1)
        self.assertFalse(os.path.exists(f1))


if __name__ == "__main__":
    unittest.main()
