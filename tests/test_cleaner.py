import os
import sys
import time
import tempfile
import unittest
from unittest.mock import patch

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

    def _create_file_with_age(self, path, size_bytes=1024, age_hours=48):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(b"x" * size_bytes)
        old_time = time.time() - (age_hours * 3600)
        os.utime(path, (old_time, old_time))

    def test_dynamic_roots_discovery(self):
        cleaner = SystemCleaner(self.safety_dry)
        self.assertIsInstance(cleaner.disposable_roots, list)
        self.assertGreater(len(cleaner.disposable_roots), 0)
        for root in cleaner.disposable_roots:
            self.assertTrue(os.path.isabs(root))
            self.assertTrue(os.path.exists(root))

    def test_preview_scan_only(self):
        cleaner = SystemCleaner(self.safety_dry)
        cleaner.disposable_roots = [self.tmpdir]

        f1 = os.path.join(self.tmpdir, "test1.tmp")
        f2 = os.path.join(self.tmpdir, "crash.dmp")
        self._create_file_with_age(f1, size_bytes=1024 * 1024, age_hours=48)
        self._create_file_with_age(f2, size_bytes=1024 * 1024, age_hours=48)

        preview = cleaner.preview()
        self.assertEqual(preview["count"], 2)
        self.assertGreaterEqual(preview["size_mb"], 2.0)
        self.assertIn("Temporary", preview["categories"])
        self.assertIn("Crash dumps", preview["categories"])

        # Verify preview does not delete files
        self.assertTrue(os.path.exists(f1))
        self.assertTrue(os.path.exists(f2))

    def test_age_filter_stale_vs_new(self):
        cleaner = SystemCleaner(self.safety_wet, min_age_hours=24)
        cleaner.disposable_roots = [self.tmpdir]

        stale_file = os.path.join(self.tmpdir, "old_stale.tmp")
        new_file = os.path.join(self.tmpdir, "new_active.tmp")

        self._create_file_with_age(stale_file, size_bytes=2048, age_hours=48)  # > 24h
        self._create_file_with_age(new_file, size_bytes=2048, age_hours=2)    # < 24h

        preview = cleaner.preview()
        self.assertEqual(preview["count"], 1)
        self.assertEqual(preview["files_skipped_new"], 1)
        self.assertEqual(preview["candidates"][0]["path"], stale_file)

        result = cleaner.execute(preview["candidates"])
        self.assertEqual(result["files_deleted"], 1)
        self.assertFalse(os.path.exists(stale_file))
        self.assertTrue(os.path.exists(new_file))

    def test_dry_run_execution_does_not_delete(self):
        cleaner = SystemCleaner(self.safety_dry)
        cleaner.disposable_roots = [self.tmpdir]

        f1 = os.path.join(self.tmpdir, "test1.tmp")
        self._create_file_with_age(f1, size_bytes=1024, age_hours=48)

        preview = cleaner.preview()
        result = cleaner.execute(preview["candidates"])

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["files_removed"], 1)
        # In dry run, file remains on disk
        self.assertTrue(os.path.exists(f1))

    def test_live_execution_deletes_safely(self):
        cleaner = SystemCleaner(self.safety_wet)
        cleaner.disposable_roots = [self.tmpdir]

        f1 = os.path.join(self.tmpdir, "clean_me.tmp")
        self._create_file_with_age(f1, size_bytes=1024, age_hours=48)

        preview = cleaner.preview()
        result = cleaner.execute(preview["candidates"])

        self.assertFalse(result["dry_run"])
        self.assertEqual(result["files_removed"], 1)
        self.assertFalse(os.path.exists(f1))

    def test_locked_file_handling_without_crash(self):
        cleaner = SystemCleaner(self.safety_wet)
        cleaner.disposable_roots = [self.tmpdir]

        f1 = os.path.join(self.tmpdir, "locked.tmp")
        self._create_file_with_age(f1, size_bytes=1024, age_hours=48)

        # Simulate PermissionError on os.unlink
        with patch("os.unlink", side_effect=PermissionError("File in use by another process")):
            candidates = cleaner.discover()
            result = cleaner.execute(candidates)

            self.assertEqual(result["files_skipped_in_use"], 1)
            self.assertEqual(result["files_deleted"], 0)
            self.assertTrue(os.path.exists(f1))

    def test_empty_subdirectory_pruning(self):
        cleaner = SystemCleaner(self.safety_wet)
        cleaner.disposable_roots = [self.tmpdir]

        nested_dir = os.path.join(self.tmpdir, "sub1", "sub2")
        f1 = os.path.join(nested_dir, "stale_nested.tmp")
        self._create_file_with_age(f1, size_bytes=1024, age_hours=48)

        candidates = cleaner.discover()
        result = cleaner.execute(candidates)

        self.assertFalse(os.path.exists(f1))
        # Empty nested folders should be pruned
        self.assertFalse(os.path.exists(nested_dir))
        # Root temporary directory itself must NEVER be removed
        self.assertTrue(os.path.exists(self.tmpdir))


if __name__ == "__main__":
    unittest.main()
