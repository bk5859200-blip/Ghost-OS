import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.core.single_instance import SingleInstance


class TestSingleInstance(unittest.TestCase):
    def test_single_instance_acquisition_and_release(self):
        mutex_name = "Local\\Test_GhostOS_Mutex_Unique_123"
        inst1 = SingleInstance(mutex_name=mutex_name)
        acquired1 = inst1.acquire()
        self.assertTrue(acquired1)

        # Second instance should be rejected if on Windows
        if sys.platform == "win32":
            inst2 = SingleInstance(mutex_name=mutex_name)
            acquired2 = inst2.acquire()
            self.assertFalse(acquired2)
            self.assertTrue(inst2.already_running)

        inst1.release()

        # After release, acquisition should succeed again
        inst3 = SingleInstance(mutex_name=mutex_name)
        acquired3 = inst3.acquire()
        self.assertTrue(acquired3)
        inst3.release()


if __name__ == "__main__":
    unittest.main()
