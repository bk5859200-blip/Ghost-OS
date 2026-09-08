import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.intelligence.rule_engine import RuleEngine
from src.intelligence.threat_sentinel import ThreatSentinel
from src.intelligence.signature_verifier import SignatureVerifier
from src.decision.decision_engine import (
    DecisionEngine, CLEAN, LOW_RISK, SUSPICIOUS, THREAT, CONFIRMED_MALWARE,
    LOG, NOTIFY, ASK_USER
)


class TestThreatDistinctionAcceptance(unittest.TestCase):
    """
    Authoritative Acceptance Tests for Threat vs Suspicious vs Low Risk Distinction.
    Guarantees Ghost OS NEVER labels harmless, unsigned, or newly downloaded files as confirmed threats.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.downloads_dir = os.path.join(self.tmpdir, "Downloads")
        self.startup_dir = os.path.join(self.tmpdir, "Startup")
        os.makedirs(self.downloads_dir, exist_ok=True)
        os.makedirs(self.startup_dir, exist_ok=True)

        self.mock_sig_verifier = MagicMock(spec=SignatureVerifier)
        self.mock_defender = MagicMock()
        self.mock_defender.is_available.return_value = True

        self.rule_engine = RuleEngine(config={}, sig_verifier=self.mock_sig_verifier)
        self.sentinel = ThreatSentinel(
            config={},
            defender_scanner=self.mock_defender,
            rule_engine=self.rule_engine
        )
        self.decision = DecisionEngine()

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_file(self, folder, name, content=b"sample binary content"):
        path = os.path.join(folder, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    # 1. Normal text file -> CLEAN
    def test_fixture_1_normal_text_file(self):
        file_path = self._create_file(self.downloads_dir, "notes.txt", b"meeting notes and todos")
        self.mock_defender.scan_file.return_value = {"scanned": False, "threat_found": False, "status": "clean"}

        analysis = self.sentinel.analyze_file(file_path, scan_with_defender=False)
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis["classification"], CLEAN)
        self.assertEqual(analysis["risk_score"], 0)

        sev, outcome, reason = self.decision.decide_for_file_risk(analysis)
        self.assertEqual(sev, CLEAN)
        self.assertIn(outcome, [LOG, "IGNORE"])
        self.assertNotIn("THREAT", sev)

    # 2. Normal signed installer (e.g. Spotify, Python, Google) -> CLEAN / LOW_RISK
    def test_fixture_2_normal_signed_installer(self):
        file_path = self._create_file(self.downloads_dir, "SpotifySetup.exe", b"MZspotifyinstaller")
        self.mock_sig_verifier.verify.return_value = {
            "valid": True,
            "publisher": "Spotify AB",
            "is_trusted_publisher": True,
            "status": "valid"
        }
        self.mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": False,
            "status": "clean",
            "detail": "No threats detected by Windows Defender."
        }

        analysis = self.sentinel.analyze_file(file_path, scan_with_defender=True)
        self.assertIsNotNone(analysis)
        self.assertIn(analysis["classification"], [CLEAN, LOW_RISK])
        self.assertLess(analysis["risk_score"], 20)
        self.assertFalse(analysis["threat_confirmed"])

        sev, outcome, reason = self.decision.decide_for_file_risk(analysis)
        self.assertIn(sev, [CLEAN, LOW_RISK])
        self.assertEqual(outcome, LOG)
        self.assertNotIn("THREAT", sev)
        self.assertIn("Spotify AB", reason)

    # 3. Unsigned executable -> LOW_RISK / SUSPICIOUS (NEVER THREAT)
    def test_fixture_3_unsigned_executable(self):
        file_path = self._create_file(self.downloads_dir, "custom_cli_tool.exe", b"MZcustomcli")
        self.mock_sig_verifier.verify.return_value = {
            "valid": False,
            "publisher": None,
            "is_trusted_publisher": False,
            "status": "unsigned"
        }
        self.mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": False,
            "status": "clean",
            "detail": "No threats detected by Windows Defender."
        }

        analysis = self.sentinel.analyze_file(file_path, scan_with_defender=True)
        self.assertIsNotNone(analysis)
        self.assertIn(analysis["classification"], [LOW_RISK, CLEAN])
        self.assertLess(analysis["risk_score"], 40)
        self.assertFalse(analysis["threat_confirmed"])

        sev, outcome, reason = self.decision.decide_for_file_risk(analysis)
        self.assertIn(sev, [LOW_RISK, CLEAN])
        self.assertEqual(outcome, LOG)
        self.assertNotIn("THREAT", sev)

    # 4. Newly downloaded executable -> LOW_RISK (NEVER THREAT)
    def test_fixture_4_newly_downloaded_executable(self):
        file_path = self._create_file(self.downloads_dir, "new_app.exe", b"MZnewapp")
        self.mock_sig_verifier.verify.return_value = {
            "valid": False,
            "publisher": None,
            "is_trusted_publisher": False,
            "status": "unsigned"
        }
        self.mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": False,
            "status": "clean",
            "detail": "No threats detected by Windows Defender."
        }

        analysis = self.sentinel.analyze_file(file_path, scan_with_defender=True)
        self.assertIsNotNone(analysis)
        self.assertIn(analysis["classification"], [LOW_RISK, CLEAN])
        self.assertLess(analysis["risk_score"], 40)

        sev, outcome, reason = self.decision.decide_for_file_risk(analysis)
        self.assertIn(sev, [LOW_RISK, CLEAN])
        self.assertEqual(outcome, LOG)
        self.assertNotIn("THREAT", sev)

    # 5. Disguised double extension (invoice.pdf.exe) -> SUSPICIOUS / THREAT (ASK_USER)
    def test_fixture_5_disguised_double_extension(self):
        file_path = self._create_file(self.downloads_dir, "invoice_Q3.pdf.exe", b"MZfakeinvoice")
        self.mock_sig_verifier.verify.return_value = {
            "valid": False,
            "publisher": None,
            "is_trusted_publisher": False,
            "status": "unsigned"
        }
        self.mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": False,
            "status": "clean",
            "detail": "No threats detected by Windows Defender."
        }

        analysis = self.sentinel.analyze_file(file_path, scan_with_defender=True)
        self.assertIsNotNone(analysis)
        self.assertGreaterEqual(analysis["risk_score"], 50)
        self.assertIn(analysis["classification"], [THREAT, SUSPICIOUS, "HIGH", "MEDIUM"])

        sev, outcome, reason = self.decision.decide_for_file_risk(analysis)
        self.assertIn(outcome, [ASK_USER, NOTIFY])
        self.assertIn(sev, [THREAT, SUSPICIOUS, "HIGH", "MEDIUM"])

    # 6. Multiple strong suspicious indicators (e.g. dropped in Startup + disguised ext) -> THREAT (ASK_USER)
    def test_fixture_6_multiple_suspicious_indicators(self):
        file_path = self._create_file(self.startup_dir, "update.docx.exe", b"MZstartupdropper")
        self.mock_sig_verifier.verify.return_value = {
            "valid": False,
            "publisher": None,
            "is_trusted_publisher": False,
            "status": "unsigned"
        }
        self.mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": False,
            "status": "clean"
        }

        analysis = self.sentinel.analyze_file(file_path, scan_with_defender=True)
        self.assertIsNotNone(analysis)
        self.assertGreaterEqual(analysis["risk_score"], 60)
        self.assertIn(analysis["classification"], [THREAT, CONFIRMED_MALWARE, "HIGH", "CRITICAL"])

        sev, outcome, reason = self.decision.decide_for_file_risk(analysis)
        self.assertEqual(outcome, ASK_USER)
        self.assertIn(sev, [THREAT, CONFIRMED_MALWARE, "HIGH", "CRITICAL"])

    # 7. Defender-confirmed threat simulation -> CONFIRMED_MALWARE (ASK_USER immediate)
    def test_fixture_7_defender_confirmed_malware(self):
        file_path = self._create_file(self.downloads_dir, "known_malware_sample.exe", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        self.mock_sig_verifier.verify.return_value = {
            "valid": False,
            "publisher": None,
            "is_trusted_publisher": False,
            "status": "unsigned"
        }
        self.mock_defender.scan_file.return_value = {
            "scanned": True,
            "threat_found": True,
            "threat_name": "Trojan:Win32/Wacatac.B!ml",
            "status": "threat_detected",
            "detail": "Trojan:Win32/Wacatac.B!ml"
        }

        analysis = self.sentinel.analyze_file(file_path, scan_with_defender=True)
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis["classification"], CONFIRMED_MALWARE)
        self.assertEqual(analysis["risk_score"], 100)
        self.assertTrue(analysis["threat_confirmed"])

        sev, outcome, reason = self.decision.decide_for_file_risk(analysis)
        self.assertEqual(sev, CONFIRMED_MALWARE)
        self.assertEqual(outcome, ASK_USER)
        self.assertIn("Trojan:Win32/Wacatac.B!ml", reason)


if __name__ == "__main__":
    unittest.main()
