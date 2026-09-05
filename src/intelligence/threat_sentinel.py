import os
import threading
import logging
from src.intelligence.rule_engine import RuleEngine
from src.intelligence.defender_scanner import DefenderScanner

logger = logging.getLogger("ghost.intelligence.threat_sentinel")

# Limit concurrent Defender MpCmdRun.exe processes to avoid system lockup
DEFENDER_SCAN_SEMAPHORE = threading.Semaphore(2)


class ThreatSentinel:
    """
    Unified threat intelligence sensor.
    Combines deterministic explainable rule scoring with on-demand Windows Defender AV scans.
    Produces clear, explainable risk reports without falsely labeling files as viruses.
    """

    def __init__(self, config=None, defender_scanner=None):
        self.config = config or {}
        self.rule_engine = RuleEngine(self.config)
        self.defender = defender_scanner or DefenderScanner()

    def analyze_file(self, file_path, scan_with_defender=True):
        """
        Runs comprehensive analysis on a file.
        Returns a dict:
          - risk_score: 0-100
          - classification: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
          - category: 'junk' | 'suspicious' | 'malware_confirmed' | None
          - signals: list of dicts [{'points': int, 'reason': str}]
          - explanation: str
          - sha256: str
          - defender_scanned: bool
          - threat_confirmed: bool
        """
        if not os.path.exists(file_path):
            return None

        # 1. Rule Engine Evaluation
        rule_eval = self.rule_engine.evaluate(file_path)

        risk_score = rule_eval["score"] if rule_eval else 0
        classification = rule_eval["classification"] if rule_eval else "LOW"
        signals = [s.to_dict() for s in rule_eval["signals"]] if rule_eval else []
        category = rule_eval["category"] if rule_eval else None
        sha256 = rule_eval.get("sha256") if rule_eval else None

        # 2. Windows Defender Scan (strictly for real executable/script extensions)
        defender_scanned = False
        threat_confirmed = False
        defender_detail = None

        if scan_with_defender and self.defender.available:
            ext = os.path.splitext(file_path)[1].lower()
            should_scan = (
                ext in RuleEngine.EXECUTABLE_EXTENSIONS or
                ext in RuleEngine.SCRIPT_EXTENSIONS
            )

            if should_scan:
                with DEFENDER_SCAN_SEMAPHORE:
                    scan_res = self.defender.scan_file(file_path)
                defender_scanned = scan_res.get("scanned", False)
                if scan_res.get("threat_found"):
                    threat_confirmed = True
                    defender_detail = scan_res.get("detail", "Windows Defender threat detection")
                    risk_score = 100
                    classification = "CRITICAL"
                    category = "malware_confirmed"
                    signals.append({"points": 100, "reason": f"Windows Defender alert: {defender_detail}"})

        explanation = self.format_report(file_path, risk_score, classification, signals, defender_detail)

        return {
            "file_path": file_path,
            "risk_score": risk_score,
            "classification": classification,
            "category": category,
            "signals": signals,
            "explanation": explanation,
            "sha256": sha256,
            "defender_scanned": defender_scanned,
            "threat_confirmed": threat_confirmed,
            "defender_detail": defender_detail
        }

    @staticmethod
    def format_report(file_path, score, classification, signals, defender_detail=None):
        lines = [
            f"Target: {os.path.basename(file_path)}",
            f"Risk Score: {score}/100 [{classification}]",
            ""
        ]
        if defender_detail:
            lines.append(f"Defender Detection: {defender_detail}")
            lines.append("")

        if signals:
            lines.append("Signals:")
            for s in signals:
                lines.append(f"  +{s['points']} {s['reason']}")
        else:
            lines.append("No abnormal signals detected.")

        return "\n".join(lines)
