import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.decision.safety_engine import SafetyEngine


class TestSafetyEngine(unittest.TestCase):
    def setUp(self):
        self.config = {
            "security": {
                "protected_processes": ["explorer.exe", "lsass.exe", "mycriticalapp.exe"],
                "protected_paths": ["C:\\Windows", "C:\\Program Files"],
            },
            "safety": {"dry_run": False},
        }
        self.engine = SafetyEngine(self.config)

    def test_protected_process_blocked(self):
        self.assertFalse(self.engine.can_act_on_process("explorer.exe"))
        self.assertFalse(self.engine.can_act_on_process("mycriticalapp.exe"))

    def test_default_system_processes_protected(self):
        self.assertFalse(self.engine.can_act_on_process("csrss.exe"))
        self.assertFalse(self.engine.can_act_on_process("python.exe"))
        self.assertFalse(self.engine.can_act_on_process("MsMpEng.exe"))

    def test_unprotected_process_allowed(self):
        self.assertTrue(self.engine.can_act_on_process("custom_random_tool.exe"))

    def test_protected_process_case_insensitive(self):
        self.assertFalse(self.engine.can_act_on_process("EXPLORER.EXE"))
        self.assertFalse(self.engine.can_act_on_process("CsRss.Exe"))

    def test_dry_run_blocks_action_regardless_of_target(self):
        dry_config = dict(self.config)
        dry_config["safety"] = {"dry_run": True}
        dry_engine = SafetyEngine(dry_config)
        allowed, reason = dry_engine.gate_action("delete", "random_tool.exe", is_process=True)
        self.assertFalse(allowed)
        self.assertEqual(reason, "dry_run")

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as allowed_root:
            outside_file = os.path.join(tempfile.gettempdir(), "outside_temp_test.txt")
            with open(outside_file, "w") as f:
                f.write("x")
            try:
                self.assertFalse(self.engine.validate_path(outside_file, [allowed_root]))
            finally:
                if os.path.exists(outside_file):
                    os.remove(outside_file)

    def test_path_inside_allowed_root_accepted(self):
        with tempfile.TemporaryDirectory() as allowed_root:
            inside_file = os.path.join(allowed_root, "inside_target.txt")
            with open(inside_file, "w") as f:
                f.write("x")
            self.assertTrue(self.engine.validate_path(inside_file, [allowed_root]))

    def test_protected_path_rejection(self):
        self.assertTrue(self.engine.is_path_protected("C:\\Windows\\System32\\cmd.exe"))
        self.assertTrue(self.engine.is_path_protected("C:\\Program Files\\app\\test.dll"))

    def test_user_media_folders_protected(self):
        docs_path = os.path.expandvars(r"%USERPROFILE%\Documents\secret.docx")
        pics_path = os.path.expandvars(r"%USERPROFILE%\Pictures\photo.png")
        vids_path = os.path.expandvars(r"%USERPROFILE%\Videos\movie.mp4")
        self.assertTrue(self.engine.is_path_protected(docs_path))
        self.assertTrue(self.engine.is_path_protected(pics_path))
        self.assertTrue(self.engine.is_path_protected(vids_path))


if __name__ == "__main__":
    unittest.main()
