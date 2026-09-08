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
    Combines deterministic explainable rule scoring, digital signature verification,
    and on-demand Windows Defender AV scans.
    Produces clear, explainable risk reports without falsely labeling files as threats.
    """

    def __init__(self, config=None, defender_scanner=None, rule_engine=None):
        self.config = config or {}
        self.rule_engine = rule_engine or RuleEngine(self.config)
        self.defender = defender_scanner or DefenderScanner()

    def analyze_file(self, file_path, scan_with_defender=True):
        """
        Runs comprehensive analysis on a file.
        Returns a dict:
          - file_path: str
          - risk_score: 0-100
          - classification: 'CLEAN' | 'LOW_RISK' | 'SUSPICIOUS' | 'THREAT' | 'CONFIRMED_MALWARE'
          - category: 'clean' | 'junk' | 'low_risk' | 'suspicious' | 'threat' | 'confirmed_malware'
          - signals: list of dicts [{'points': int, 'reason': str}]
          - explanation: str
          - sha256: str
          - publisher: str or None
          - signature_status: str
          - signature_valid: bool
          - defender_scanned: bool
          - threat_confirmed: bool
          - defender_detail: str or None
          - defender_status: 'DEFENDER_CLEAN' | 'DEFENDER_THREAT' | 'DEFENDER_UNAVAILABLE' | 'DEFENDER_ERROR' | 'DEFENDER_TIMEOUT' | None
        """
        if not os.path.exists(file_path):
            return None

        # 1. Rule Engine & Signature Evaluation
        rule_eval = self.rule_engine.evaluate(file_path)

        risk_score = rule_eval["score"] if rule_eval else 0
        classification = rule_eval["classification"] if rule_eval else "CLEAN"
        signals = [s.to_dict() if hasattr(s, "to_dict") else s for s in rule_eval.get("signals", [])] if rule_eval else []
        category = rule_eval.get("category", "clean") if rule_eval else "clean"
        sha256 = rule_eval.get("sha256") if rule_eval else None
        sig_info = rule_eval.get("signature_info") if rule_eval else None

        publisher = sig_info.get("publisher") if sig_info else None
        signature_status = sig_info.get("status") if sig_info else "unknown"
        signature_valid = bool(sig_info.get("valid")) if sig_info else False

        # 2. Windows Defender Scan (strictly for real executable/script extensions)
        defender_scanned = False
        threat_confirmed = False
        defender_detail = None
        defender_status = "DEFENDER_UNAVAILABLE"

        defender_avail = False
        if hasattr(self.defender, "is_available") and callable(self.defender.is_available):
            defender_avail = self.defender.is_available()
        elif hasattr(self.defender, "available"):
            defender_avail = bool(self.defender.available)

        if scan_with_defender and defender_avail:
            ext = os.path.splitext(file_path)[1].lower()
            should_scan = (
                ext in RuleEngine.EXECUTABLE_EXTENSIONS or
                ext in RuleEngine.SCRIPT_EXTENSIONS
            )

            if should_scan:
                with DEFENDER_SCAN_SEMAPHORE:
                    scan_res = self.defender.scan_file(file_path)
                defender_scanned = scan_res.get("scanned", False)
                raw_status = scan_res.get("status")

                if scan_res.get("threat_found") or raw_status == "threat_detected":
                    threat_confirmed = True
                    defender_status = "DEFENDER_THREAT"
                    defender_detail = scan_res.get("detail", "Windows Defender threat detection")
                    risk_score = 100
                    classification = "CONFIRMED_MALWARE"
                    category = "confirmed_malware"
                    signals.append({"points": 100, "reason": f"Windows Defender alert: {defender_detail}"})
                elif raw_status == "clean":
                    defender_status = "DEFENDER_CLEAN"
                    defender_detail = "Clean (No threats detected by Windows Defender)"
                elif raw_status == "timeout":
                    defender_status = "DEFENDER_TIMEOUT"
                    defender_detail = "Windows Defender scan timed out"
                elif raw_status == "scan_error":
                    defender_status = "DEFENDER_ERROR"
                    defender_detail = scan_res.get("detail", "Defender scan error")
                elif raw_status == "unavailable":
                    defender_status = "DEFENDER_UNAVAILABLE"
                    defender_detail = "Defender CLI unavailable"
        elif not defender_avail:
            defender_status = "DEFENDER_UNAVAILABLE"
            defender_detail = "Defender CLI not available"

        explanation = self.format_report(
            file_path, risk_score, classification, signals,
            publisher=publisher, signature_status=signature_status,
            defender_detail=defender_detail, threat_confirmed=threat_confirmed,
            defender_status=defender_status
        )

        return {
            "file_path": file_path,
            "risk_score": risk_score,
            "classification": classification,
            "category": category,
            "signals": signals,
            "explanation": explanation,
            "sha256": sha256,
            "publisher": publisher,
            "signature_status": signature_status,
            "signature_valid": signature_valid,
            "defender_scanned": defender_scanned,
            "threat_confirmed": threat_confirmed,
            "defender_detail": defender_detail,
            "defender_status": defender_status
        }

    @staticmethod
    def format_report(file_path, score, classification, signals, publisher=None,
                      signature_status=None, defender_detail=None, threat_confirmed=False,
                      defender_status=None):
        lines = [
            f"Target: {os.path.basename(file_path)}",
            f"Risk Score: {score}/100 [{classification}]"
        ]

        if publisher:
            lines.append(f"Publisher: {publisher}")
        if signature_status and signature_status != "unknown":
            lines.append(f"Signature Status: {signature_status.capitalize()}")

        lines.append("")

        if defender_detail:
            lines.append(f"Defender Status ({defender_status or 'N/A'}): {defender_detail}")
            lines.append("")

        if signals:
            lines.append("Signals:")
            for s in signals:
                sign = "+" if s.get("points", 0) > 0 else ""
                lines.append(f"  {sign}{s.get('points', 0)} {s.get('reason', '')}")
        else:
            lines.append("No abnormal signals detected.")

        return "\n".join(lines)
