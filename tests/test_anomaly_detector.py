import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.intelligence.anomaly_detector import AnomalyDetector


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.detector = AnomalyDetector(model_dir=self.tmpdir)

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_stage_a_rules_detection(self):
        normal_metrics = {"cpu_percent": 15.0, "ram_percent": 45.0}
        thresholds = {
            "cpu": {"critical_percent": 90.0},
            "memory": {"critical_percent": 95.0}
        }
        res_normal = self.detector.evaluate_rules(normal_metrics, thresholds)
        self.assertEqual(len(res_normal), 0)

        spike_metrics = {"cpu_percent": 96.0, "ram_percent": 45.0}
        res_spike = self.detector.evaluate_rules(spike_metrics, thresholds)
        self.assertEqual(len(res_spike), 1)
        self.assertEqual(res_spike[0]["type"], "cpu_critical")

    def test_stage_b_baseline_deviation(self):
        # Populate historical baseline (35 samples of low CPU around 10%)
        for _ in range(35):
            self.detector.add_telemetry_sample({
                "cpu_percent": 10.0,
                "ram_percent": 30.0,
                "disk_used_percent": 50.0,
                "disk_read_rate_mb": 0.5,
                "disk_write_rate_mb": 0.5,
                "net_sent_rate_mb": 0.1,
                "net_recv_rate_mb": 0.1
            })

        # Test normal sample
        normal_res = self.detector.evaluate_baseline({
            "cpu_percent": 11.0,
            "ram_percent": 30.5,
            "disk_used_percent": 50.0,
            "disk_read_rate_mb": 0.5,
            "disk_write_rate_mb": 0.5,
            "net_sent_rate_mb": 0.1,
            "net_recv_rate_mb": 0.1
        })
        self.assertIsNone(normal_res)

        # Test sudden extreme deviation (CPU jumps to 95%)
        anomaly_res = self.detector.evaluate_baseline({
            "cpu_percent": 95.0,
            "ram_percent": 30.0,
            "disk_used_percent": 50.0,
            "disk_read_rate_mb": 0.5,
            "disk_write_rate_mb": 0.5,
            "net_sent_rate_mb": 0.1,
            "net_recv_rate_mb": 0.1
        }, z_threshold=3.0)
        self.assertIsNotNone(anomaly_res)
        self.assertTrue(anomaly_res["is_anomaly"])
        self.assertEqual(anomaly_res["feature"], "CPU")


if __name__ == "__main__":
    unittest.main()
