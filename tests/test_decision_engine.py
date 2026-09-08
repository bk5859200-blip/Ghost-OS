import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.decision.decision_engine import (
    DecisionEngine, CLEAN, LOW_RISK, SUSPICIOUS, THREAT, CONFIRMED_MALWARE,
    INFO, LOW, MEDIUM, HIGH, CRITICAL,
    IGNORE, LOG, NOTIFY, ASK_USER
)


class TestDecisionEngine(unittest.TestCase):
    def setUp(self):
        self.decision = DecisionEngine()

    def test_decide_for_clean_file(self):
        rule_res = {"score": 0, "classification": "CLEAN", "signals": [], "category": "clean"}
        sev, outcome, reason = self.decision.decide_for_file_risk(rule_res)
        self.assertEqual(sev, CLEAN)
        self.assertEqual(outcome, LOG)

    def test_decide_for_none_file_result(self):
        sev, outcome, reason = self.decision.decide_for_file_risk(None)
        self.assertEqual(sev, CLEAN)
        self.assertEqual(outcome, IGNORE)

    def test_decide_for_low_risk_file(self):
        rule_res = {
            "score": 25,
            "classification": "LOW_RISK",
            "signals": [{"points": 10, "reason": "Newly arrived in Downloads"}, {"points": 5, "reason": "Unsigned binary"}],
            "category": "low_risk"
        }
        sev, outcome, reason = self.decision.decide_for_file_risk(rule_res)
        self.assertEqual(sev, LOW_RISK)
        self.assertEqual(outcome, LOG)

    def test_decide_for_medium_suspicious_file(self):
        rule_res = {
            "score": 45,
            "classification": "SUSPICIOUS",
            "signals": [{"points": 20, "reason": "Script in weird path"}],
            "category": "suspicious"
        }
        sev, outcome, reason = self.decision.decide_for_file_risk(rule_res)
        self.assertEqual(sev, SUSPICIOUS)
        self.assertEqual(outcome, NOTIFY)

    def test_decide_for_high_risk_file(self):
        rule_res = {
            "score": 75,
            "classification": "THREAT",
            "signals": [{"points": 35, "reason": "Startup drop"}, {"points": 40, "reason": "Disguised ext"}],
            "category": "threat"
        }
        sev, outcome, reason = self.decision.decide_for_file_risk(rule_res)
        self.assertEqual(sev, THREAT)
        self.assertEqual(outcome, ASK_USER)

    def test_decide_for_critical_file(self):
        rule_res = {
            "score": 90,
            "classification": "CONFIRMED_MALWARE",
            "signals": [{"points": 50, "reason": "Disguised double ext"}],
            "category": "confirmed_malware"
        }
        sev, outcome, reason = self.decision.decide_for_file_risk(rule_res)
        self.assertEqual(sev, CONFIRMED_MALWARE)
        self.assertEqual(outcome, ASK_USER)

    def test_decide_for_defender_flagged(self):
        defender_res = {"scanned": True, "threat_found": True, "detail": "Trojan.Win32.Generic"}
        sev, outcome, reason = self.decision.decide_for_file_risk(None, defender_result=defender_res)
        self.assertEqual(sev, CONFIRMED_MALWARE)
        self.assertEqual(outcome, ASK_USER)
        self.assertIn("Trojan.Win32.Generic", reason)

    def test_decide_for_cpu_spikes(self):
        # Brief spike
        sev_brief, out_brief, _ = self.decision.decide_for_resource_anomaly("CPU", 95.0, 90.0, persistent=False)
        self.assertEqual(sev_brief, LOW_RISK)
        self.assertEqual(out_brief, LOG)

        # Persistent spike
        sev_pers, out_pers, _ = self.decision.decide_for_resource_anomaly("CPU", 95.0, 90.0, persistent=True)
        self.assertEqual(sev_pers, SUSPICIOUS)
        self.assertEqual(out_pers, NOTIFY)

    def test_decide_for_process_spawns(self):
        # Benign
        sev1, out1, _ = self.decision.decide_for_process_spawn(False, None)
        self.assertEqual(sev1, CLEAN)
        self.assertEqual(out1, LOG)

        # Suspicious spawn
        sev2, out2, _ = self.decision.decide_for_process_spawn(True, "Document spawned cmd")
        self.assertEqual(sev2, THREAT)
        self.assertEqual(out2, NOTIFY)


if __name__ == "__main__":
    unittest.main()
