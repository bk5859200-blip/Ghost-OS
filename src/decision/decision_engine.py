import logging

logger = logging.getLogger("ghost.decision.decision_engine")

# Severity levels (Master Spec Section 14)
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
CLEAN = "CLEAN"
QUARANTINE = "QUARANTINE"
SAFE_ACTION = "SAFE_ACTION"


class DecisionEngine:
    """
    Evaluates risk signals and contextual evidence to determine the exact action Ghost should take.
    Enforces 'unknown != malicious': actions default to LOG/NOTIFY rather than destructive measures.
    """

    def decide_for_file_risk(self, rule_result, defender_result=None):
        """
        Evaluates file risk report and optional Defender verdict.
        :return: (severity: str, outcome: str, reason: str)
        """
        # If Defender explicitly confirmed a threat
        if defender_result and defender_result.get("scanned") and defender_result.get("threat_found"):
            return CRITICAL, ASK_USER, defender_result.get("detail", "Windows Defender flagged this file")

        if not rule_result:
            return INFO, IGNORE, "No abnormal signals"

        score = rule_result.get("risk_score", rule_result.get("score", 0))
        classification = rule_result.get("classification", "LOW")
        category = rule_result.get("category")
        signals = rule_result.get("signals", [])

        reasons_list = []
        for s in signals:
            if isinstance(s, dict):
                reasons_list.append(s.get("reason", ""))
            elif hasattr(s, "reason"):
                reasons_list.append(s.reason)
        reasons = "; ".join(r for r in reasons_list if r) if reasons_list else "No signals"

        if classification == "LOW" or score < 30:
            return LOW, LOG, f"Low-confidence signal ({score}/100): {reasons}"

        if classification == "MEDIUM":
            outcome = ASK_USER if category == "suspicious" else NOTIFY
            return MEDIUM, outcome, f"Medium risk ({score}/100): {reasons}"

        if classification == "HIGH":
            return HIGH, ASK_USER, f"High risk ({score}/100): {reasons}"

        # CRITICAL (Score >= 80)
        return CRITICAL, ASK_USER, f"Critical risk ({score}/100): {reasons}"

    def decide_for_resource_anomaly(self, metric_name, value, threshold, persistent=False):
        if not persistent:
            return LOW, LOG, f"{metric_name} briefly peaked at {value:.1f}% (threshold: {threshold}%)"
        return MEDIUM, NOTIFY, f"{metric_name} usage remained at {value:.1f}% above limit ({threshold}%) for a sustained period"

    def decide_for_process_spawn(self, is_suspicious_spawn, spawn_reason):
        if is_suspicious_spawn:
            return HIGH, NOTIFY, spawn_reason
        return INFO, LOG, "Normal process execution"
