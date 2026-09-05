import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.sensors.system_sensor import SystemSensor


class TestSystemSensor(unittest.TestCase):
    def setUp(self):
        self.sensor = SystemSensor()

    def test_collect_metrics_structure(self):
        metrics = self.sensor.collect_metrics()
        self.assertIsInstance(metrics, dict)
        self.assertIn("cpu_percent", metrics)
        self.assertIn("ram_percent", metrics)
        self.assertIn("available_ram_mb", metrics)
        self.assertIn("disk_used_percent", metrics)
        self.assertIn("disk_free_gb", metrics)
        self.assertIn("disk_read_rate_mb", metrics)
        self.assertIn("disk_write_rate_mb", metrics)
        self.assertIn("net_sent_rate_mb", metrics)
        self.assertIn("net_recv_rate_mb", metrics)
        self.assertIn("process_count", metrics)
        self.assertIn("uptime_seconds", metrics)

    def test_uptime_calculation(self):
        uptime = self.sensor.get_system_uptime_seconds()
        self.assertIsInstance(uptime, int)
        self.assertGreaterEqual(uptime, 0)

    def test_process_count_positive(self):
        metrics = self.sensor.collect_metrics()
        self.assertGreater(metrics["process_count"], 0)

    def test_io_rates_non_negative(self):
        metrics = self.sensor.collect_metrics()
        self.assertGreaterEqual(metrics["disk_read_rate_mb"], 0.0)
        self.assertGreaterEqual(metrics["disk_write_rate_mb"], 0.0)
        self.assertGreaterEqual(metrics["net_sent_rate_mb"], 0.0)
        self.assertGreaterEqual(metrics["net_recv_rate_mb"], 0.0)


if __name__ == "__main__":
    unittest.main()
