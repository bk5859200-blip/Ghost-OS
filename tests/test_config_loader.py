import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.config_loader import load_config, ConfigError


class TestConfigLoader(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_yaml(self, content):
        path = os.path.join(self.tmpdir, "policy.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_load_valid_config(self):
        valid_yaml = r"""
ghost:
  startup: true
monitoring:
  system_interval_seconds: 2
  process_interval_seconds: 5
  db_cleanup_days: 7
thresholds:
  cpu:
    critical_percent: 90
    consecutive_ticks: 3
  memory:
    critical_percent: 95
  disk:
    warning_percent: 90
notifications:
  enabled: true
  cooldown_seconds: 120
  aggregate_window_seconds: 300
watch_folders:
  - "%TEMP%"
cleanup:
  enabled: true
  require_confirmation: true
  stale_installer_days: 30
  stale_temp_days: 14
security:
  protected_processes:
    - "explorer.exe"
  protected_paths:
    - 'C:\Windows'
automation:
  enabled: true
safety:
  dry_run: true
"""
        path = self._write_yaml(valid_yaml)
        config = load_config(path)
        self.assertIsInstance(config, dict)
        self.assertTrue(config["safety"]["dry_run"])
        self.assertEqual(config["monitoring"]["system_interval_seconds"], 2)

    def test_missing_required_section_raises(self):
        invalid_yaml = "ghost:\n  startup: true\n"
        path = self._write_yaml(invalid_yaml)
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_nonexistent_config_raises(self):
        with self.assertRaises(ConfigError):
            load_config(os.path.join(self.tmpdir, "does_not_exist.yaml"))

    def test_invalid_numeric_raises(self):
        invalid_num = r"""
ghost:
  startup: true
monitoring:
  system_interval_seconds: 0.1
  process_interval_seconds: 5
  db_cleanup_days: 7
thresholds:
  cpu:
    critical_percent: 90
    consecutive_ticks: 3
  memory:
    critical_percent: 95
  disk:
    warning_percent: 90
notifications:
  enabled: true
  cooldown_seconds: 120
  aggregate_window_seconds: 300
watch_folders:
  - "%TEMP%"
cleanup:
  enabled: true
  require_confirmation: true
  stale_installer_days: 30
  stale_temp_days: 14
security:
  protected_processes: []
  protected_paths: []
automation:
  enabled: true
safety:
  dry_run: true
"""
        path = self._write_yaml(invalid_num)
        with self.assertRaises(ConfigError):
            load_config(path)


if __name__ == "__main__":
    unittest.main()
