import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.autostart.autostart_manager import _pythonw_launch_command, is_registered_registry_run, sync_autostart_state


class TestAutostartManager(unittest.TestCase):
    def test_pythonw_launch_command_structure(self):
        pythonw_exe, script_path = _pythonw_launch_command()
        self.assertTrue("python" in pythonw_exe.lower())
        self.assertTrue(script_path.endswith("ghost_os_main.py"))
        self.assertTrue(os.path.isabs(script_path))

    def test_is_registered_returns_bool(self):
        result = is_registered_registry_run()
        self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main()
