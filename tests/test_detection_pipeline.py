import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.intelligence.rule_engine import RuleEngine
from src.intelligence.threat_sentinel import ThreatSentinel
from src.intelligence.defender_scanner import DefenderScanner
from src.decision.decision_engine import DecisionEngine, ASK_USER, CRITICAL, MEDIUM, HIGH
from src.notifications.notifier import Notifier


class TestDetectionPipeline(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = {
            "rules": {
                "scan_double_extensions": True,
                "scan_script_files": True
            }
        }
        self.rule_engine = RuleEngine(self.config)

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_temp_file(self, filename, content=b"sample payload"):
        path = os.path.join(self.tmpdir, filename)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_double_extension_detection_and_decision(self):
        """Disguised executable (.pdf.exe) receives >= 35 score, category suspicious, and escalates to ASK_USER."""
        path = self._create_temp_file("financial_report.pdf.exe")
        eval_result = self.rule_engine.evaluate(path)
        
        self.assertIsNotNone(eval_result)
        self.assertGreaterEqual(eval_result["score"], 35)
        self.assertEqual(eval_result["category"], "suspicious")
        self.assertIn(eval_result["classification"], ["MEDIUM", "HIGH", "CRITICAL"])

        # DecisionEngine escalation
        decision_engine = DecisionEngine()
        severity, outcome, reason = decision_engine.decide_for_file_risk(eval_result)
        self.assertEqual(outcome, ASK_USER)
        self.assertIn(severity, [MEDIUM, HIGH, CRITICAL])

    def test_suspicious_script_detection(self):
        """Script files like .ps1 or .vbs receive points and flagged appropriately."""
        path = self._create_temp_file("installer_hook.ps1", b"Invoke-Expression 'test'")
        eval_result = self.rule_engine.evaluate(path)
        
        self.assertIsNotNone(eval_result)
        self.assertGreater(eval_result["score"], 0)
        self.assertTrue(any("Script file" in s.reason for s in eval_result["signals"]))

    def test_threat_sentinel_with_defender_clean_status(self):
        """ThreatSentinel reports clean status without false-positive critical alarm."""
        mock_defender = MagicMock()
        mock_defender.is_available.return_value = True
        mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": False,
            "status": "clean",
            "detail": "No threats detected by Windows Defender."
        }

        sentinel = ThreatSentinel(config=self.config, defender_scanner=mock_defender)
        path = self._create_temp_file("trusted_tool.exe")
        report = sentinel.analyze_file(path)

        self.assertIsNotNone(report)
        self.assertFalse(report["threat_confirmed"])
        self.assertEqual(report["defender_status"], "clean")
        self.assertIn("No threats detected", report["explanation"])

    def test_threat_sentinel_with_defender_scan_error_does_not_flag_malware(self):
        """Scan errors / exit code anomalies must NOT be classified as confirmed malware."""
        mock_defender = MagicMock()
        mock_defender.is_available.return_value = True
        mock_defender.scan_file.return_value = {
            "scanned": False,
            "threat_found": False,
            "status": "scan_error",
            "detail": "MpCmdRun returned exit code 1"
        }

        sentinel = ThreatSentinel(config=self.config, defender_scanner=mock_defender)
        path = self._create_temp_file("system_util.exe")
        report = sentinel.analyze_file(path)

        self.assertIsNotNone(report)
        self.assertFalse(report["threat_confirmed"])
        self.assertNotEqual(report["category"], "malware_confirmed")
        self.assertEqual(report["defender_status"], "scan_error")

    def test_threat_sentinel_with_defender_threat_detected(self):
        """Confirmed malware results in score 100, CRITICAL classification, and category malware_confirmed."""
        mock_defender = MagicMock()
        mock_defender.is_available.return_value = True
        mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": True,
            "threat_name": "Trojan:Win32/TestThreat",
            "status": "threat_detected",
            "detail": "Trojan:Win32/TestThreat"
        }

        sentinel = ThreatSentinel(config=self.config, defender_scanner=mock_defender)
        path = self._create_temp_file("trojan_sample.exe")
        report = sentinel.analyze_file(path)

        self.assertIsNotNone(report)
        self.assertTrue(report["threat_confirmed"])
        self.assertEqual(report["classification"], "CRITICAL")
        self.assertEqual(report["risk_score"], 100)
        self.assertEqual(report["category"], "malware_confirmed")
        self.assertIn("Trojan:Win32/TestThreat", report["explanation"])

    def test_notification_fallback_to_ui_alert(self):
        """When Windows native toast delivery fails, fallback alert handler is called."""
        fallback_called = []

        def fallback_handler(event_id, file_path, reason, severity):
            fallback_called.append({
                "event_id": event_id,
                "file_path": file_path,
                "reason": reason,
                "severity": severity
            })

        notifier = Notifier(enabled=True, fallback_alert_handler=fallback_handler)
        
        # Force _show_toast to return False (simulating toast failure)
        with patch.object(notifier, "_show_toast", return_value=False):
            on_response = MagicMock()
            notifier.alert_detection(
                event_id="evt_test_123",
                file_path=r"C:\Downloads\bad.exe",
                reason="Malware detected",
                severity="CRITICAL",
                on_response=on_response
            )
            self.assertEqual(len(fallback_called), 1)
            self.assertEqual(fallback_called[0]["severity"], "CRITICAL")
            self.assertEqual(fallback_called[0]["file_path"], r"C:\Downloads\bad.exe")
            self.assertEqual(fallback_called[0]["event_id"], "evt_test_123")


if __name__ == "__main__":
    unittest.main()
