import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.proc_utils import run_hidden, popen_hidden


class TestProcUtils(unittest.TestCase):
    def test_run_hidden_echo(self):
        cmd = ["cmd.exe", "/c", "echo", "GhostOS_Hidden_Test"]
        res = run_hidden(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("GhostOS_Hidden_Test", res.stdout)

    def test_popen_hidden(self):
        cmd = ["cmd.exe", "/c", "echo", "GhostOS_Popen_Test"]
        proc = popen_hidden(cmd, stdout=subprocess_stdout(), text=True)
        stdout, _ = proc.communicate(timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("GhostOS_Popen_Test", stdout)


def subprocess_stdout():
    import subprocess
    return subprocess.PIPE


if __name__ == "__main__":
    unittest.main()
