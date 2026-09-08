import logging

logger = logging.getLogger("ghost.decision.decision_engine")

# Canonical Explicit Security Classifications
CLEAN = "CLEAN"
LOW_RISK = "LOW_RISK"
SUSPICIOUS = "SUSPICIOUS"
THREAT = "THREAT"
CONFIRMED_MALWARE = "CONFIRMED_MALWARE"

# Severity levels (Master Spec Section 14 / legacy mapping)
INFO = "INFO"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

# Outcomes an event can resolve to (Master Spec Section 19)
IGNORE = "IGNORE"
LOG = "LOG"
NOTIFY = "NOTIFY"
ASK_USER = "ASK_USER"
QUARANTINE = "QUARANTINE"
SAFE_ACTION = "SAFE_ACTION"

# Defender Integration Statuses
DEFENDER_CLEAN = "DEFENDER_CLEAN"
DEFENDER_THREAT = "DEFENDER_THREAT"
DEFENDER_UNAVAILABLE = "DEFENDER_UNAVAILABLE"
DEFENDER_ERROR = "DEFENDER_ERROR"
DEFENDER_TIMEOUT = "DEFENDER_TIMEOUT"


class DecisionEngine:
    """
    Authoritative decision engine for Ghost OS security intelligence.
    Evaluates rule signals, digital signatures, publisher reputation, and Defender verdicts
    to produce deterministic classifications and action recommendations.

    Enforces 'unknown != malicious':
      - Normal, unsigned, or newly downloaded executables are classified as LOW_RISK / CLEAN (silent audit).
      - Suspicious traits are classified as SUSPICIOUS (Activity view / non-disruptive notify).
      - Strong malicious traits or disguised double extensions are classified as THREAT (interactive prompt).
      - Defender detections are classified as CONFIRMED_MALWARE (immediate security alert).
    """

    def decide_for_file_risk(self, rule_result, defender_result=None):
        """
        Evaluates file risk report and optional Defender verdict.
        :return: (classification: str, outcome: str, reason: str)
        """
        # 1. Defender-confirmed threat override -> Immediate CONFIRMED_MALWARE
        if defender_result and defender_result.get("scanned") and defender_result.get("threat_found"):
            threat_name = defender_result.get("threat_name") or defender_result.get("detail", "Windows Defender threat detection")
            return CONFIRMED_MALWARE, ASK_USER, f"Windows Defender confirmed threat: {threat_name}"

        if rule_result and rule_result.get("threat_confirmed"):
            detail = rule_result.get("defender_detail") or "Windows Defender confirmed threat"
            return CONFIRMED_MALWARE, ASK_USER, f"Confirmed Malware: {detail}"

        if not rule_result:
            return CLEAN, IGNORE, "Clean (no abnormal signals detected)"

        score = rule_result.get("risk_score", rule_result.get("score", 0))
        raw_class = str(rule_result.get("classification", "CLEAN")).upper()
        signals = rule_result.get("signals", [])
        sig_info = rule_result.get("signature_info") or {}
        pub = rule_result.get("publisher") or sig_info.get("publisher")
        sig_status = rule_result.get("signature_status") or sig_info.get("status")
        defender_status = rule_result.get("defender_status")

        reasons_list = []
        for s in signals:
            if isinstance(s, dict):
                reasons_list.append(s.get("reason", ""))
            elif hasattr(s, "reason"):
                reasons_list.append(s.reason)
        reasons = "; ".join(r for r in reasons_list if r) if reasons_list else ""

        # Build informative reason string with signature and defender context
        context_parts = []
        if pub:
            context_parts.append(f"Publisher: {pub}")
        elif sig_status == "valid":
            context_parts.append("Valid digital signature")
        elif sig_status == "unsigned":
            context_parts.append("Unsigned binary")

        if defender_status == DEFENDER_CLEAN or defender_status == "clean":
            context_parts.append("Defender: Clean")
        elif defender_status in (DEFENDER_UNAVAILABLE, "unavailable"):
            context_parts.append("Defender: Unavailable")
        elif defender_status in (DEFENDER_ERROR, "scan_error"):
            context_parts.append("Defender: Error")
        elif defender_status in (DEFENDER_TIMEOUT, "timeout"):
            context_parts.append("Defender: Timeout")

        if reasons:
            context_parts.append(reasons)

        full_reason = " | ".join(context_parts) if context_parts else "Standard file characteristics"

        # 2. Canonical Classification Decision
        if score >= 80 or raw_class in ("CRITICAL", "CONFIRMED_MALWARE"):
            return CONFIRMED_MALWARE, ASK_USER, f"Critical risk ({score}/100): {full_reason}"

        if score >= 60 or raw_class in ("HIGH", "THREAT", "THREAT_DETECTED"):
            return THREAT, ASK_USER, f"Threat indicators detected ({score}/100): {full_reason}"

        if score >= 40 or raw_class in ("MEDIUM", "SUSPICIOUS"):
            return SUSPICIOUS, NOTIFY, f"Suspicious traits ({score}/100): {full_reason}"

        if score >= 20 or raw_class in ("LOW", "LOW_RISK"):
            return LOW_RISK, LOG, f"Low risk ({score}/100): {full_reason}"

        return CLEAN, LOG, f"Clean ({score}/100): {full_reason}"

    def decide_for_resource_anomaly(self, metric_name, value, threshold, persistent=False):
        if not persistent:
            return LOW_RISK, LOG, f"{metric_name} briefly peaked at {value:.1f}% (threshold: {threshold}%)"
        return SUSPICIOUS, NOTIFY, f"{metric_name} usage remained at {value:.1f}% above limit ({threshold}%) for a sustained period"

    def decide_for_process_spawn(self, is_suspicious_spawn, spawn_reason):
        if is_suspicious_spawn:
            return THREAT, NOTIFY, spawn_reason
        return CLEAN, LOG, "Normal process execution"
