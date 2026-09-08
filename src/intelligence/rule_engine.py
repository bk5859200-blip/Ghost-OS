import os
import time
import hashlib
import logging
from src.intelligence.signature_verifier import SignatureVerifier

logger = logging.getLogger("ghost.intelligence.rule_engine")


class RiskSignal:
    """One explainable contribution to a file's risk score."""
    __slots__ = ("points", "reason")

    def __init__(self, points: int, reason: str):
        self.points = points
        self.reason = reason

    def to_dict(self):
        return {"points": self.points, "reason": self.reason}


class RuleEngine:
    """
    Deterministic, explainable risk scoring for files and filesystem drops.
    Integrates Authenticode signature verification, publisher reputation,
    file characteristics, location context, and heuristics.

    Score bands & canonical classifications:
      0-19   CLEAN             (informational / clean, log only, zero disruptive alert)
      20-39  LOW_RISK          (weak indicators / unsigned download, audit logged, no popup)
      40-59  SUSPICIOUS        (multiple indicators justifying review, activity logged)
      60-79  THREAT            (suspicious disguised or multiple high-risk indicators, interactive prompt)
      80-100 CONFIRMED_MALWARE (confirmed malware or extreme risk, immediate alert & quarantine option)
    """

    SUSPICIOUS_DOUBLE_EXTENSIONS = [
        ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
        ".jpg.exe", ".png.exe", ".txt.exe", ".zip.exe", ".mp4.exe",
        ".jpg.scr", ".png.scr", ".docx.scr", ".pdf.scr",
        ".pdf.cmd", ".png.bat", ".docx.vbs", ".pdf.ps1"
    ]
    EXECUTABLE_EXTENSIONS = [".exe", ".msi", ".dll", ".scr", ".com", ".pif", ".cpl"]
    SCRIPT_EXTENSIONS = [".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".wsf"]
    ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".iso", ".img", ".vhd"]
    JUNK_EXTENSIONS = [".tmp", ".log", ".bak", ".old", ".chk"]

    def __init__(self, config=None, sig_verifier=None):
        cleanup_cfg = (config or {}).get("cleanup", {})
        self.stale_installer_days = cleanup_cfg.get("stale_installer_days", 30)
        self.stale_temp_days = cleanup_cfg.get("stale_temp_days", 14)
        self.sig_verifier = sig_verifier or SignatureVerifier()

    def calculate_sha256(self, file_path, max_bytes=10 * 1024 * 1024):
        """Calculates SHA-256 for files up to max_bytes without reading massive files entirely into memory."""
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
                    if f.tell() > max_bytes:
                        break
            return h.hexdigest()
        except Exception:
            return None

    def evaluate(self, file_path):
        """
        Evaluates a file and returns a structured risk report with digital signature context.
        Returns None if file does not exist.
        """
        if not os.path.exists(file_path):
            return None

        name = os.path.basename(file_path).lower()
        ext = os.path.splitext(name)[1].lower()
        file_path_norm = os.path.normpath(file_path).lower()
        signals = []

        # 1. Disguised double extensions (e.g. invoice.pdf.exe) -> Strong threat signal (+50)
        for double_ext in self.SUSPICIOUS_DOUBLE_EXTENSIONS:
            if name.endswith(double_ext):
                signals.append(RiskSignal(50, f"Disguised executable format (ends with '{double_ext}')"))
                break

        # 2. Executable in temporary, download, or startup persistence location
        if ext in self.EXECUTABLE_EXTENSIONS:
            if "\\startup\\" in file_path_norm or "start menu\\programs\\startup" in file_path_norm:
                signals.append(RiskSignal(45, "Executable dropped directly into Startup persistence folder"))
            elif "\\temp\\" in file_path_norm or "\\appdata\\local\\temp" in file_path_norm:
                signals.append(RiskSignal(15, "Executable located in temporary directory"))
            elif "\\downloads\\" in file_path_norm:
                signals.append(RiskSignal(10, "Newly arrived executable in Downloads"))

        # 3. Scripts in unusual locations
        if ext in self.SCRIPT_EXTENSIONS:
            if self._in_unusual_location(file_path):
                signals.append(RiskSignal(20, f"Script file ({ext}) located in non-standard user folder"))
            if "\\temp\\" in file_path_norm:
                signals.append(RiskSignal(15, f"Script file ({ext}) dropped into Temp"))

        # 4. Hidden or system attribute abuse / Suspicious executable naming
        if any(name.startswith(prefix) for prefix in [".", "~$"]) and ext in self.EXECUTABLE_EXTENSIONS:
            signals.append(RiskSignal(30, "Hidden/obfuscated executable name"))

        # 5. Authenticode digital signature & publisher reputation check for binaries
        sig_info = None
        if ext in self.EXECUTABLE_EXTENSIONS or ext in (".dll", ".sys"):
            try:
                sig_info = self.sig_verifier.verify(file_path)
                if sig_info.get("valid"):
                    pub = sig_info.get("publisher") or "Verified Publisher"
                    if sig_info.get("is_trusted_publisher"):
                        signals.append(RiskSignal(-35, f"Valid digital signature from trusted publisher: {pub}"))
                    else:
                        signals.append(RiskSignal(-25, f"Valid digital signature: {pub}"))
                elif sig_info.get("status") in ("hashmismatch", "nottrusted", "baddigest"):
                    signals.append(RiskSignal(35, f"Digital signature verification failed ({sig_info.get('status')})"))
                else:
                    signals.append(RiskSignal(5, "Unsigned executable"))
            except Exception as e:
                logger.debug(f"Signature evaluation error: {e}")

        try:
            mtime = os.path.getmtime(file_path)
            age_days = (time.time() - mtime) / 86400.0
        except OSError:
            age_days = 0

        # 6. Stale installers / temp clutter (junk category)
        is_junk = False
        if ext in self.EXECUTABLE_EXTENSIONS and "downloads" in file_path_norm and age_days > self.stale_installer_days:
            signals.append(RiskSignal(10, f"Installer unaccessed for {int(age_days)} days"))
            is_junk = True

        if ext in self.JUNK_EXTENSIONS and age_days > self.stale_temp_days:
            signals.append(RiskSignal(10, f"Temporary file untouched for {int(age_days)} days"))
            is_junk = True

        try:
            if os.path.getsize(file_path) == 0 and age_days > 1:
                signals.append(RiskSignal(5, "Zero-byte empty file, older than 1 day"))
                is_junk = True
        except OSError:
            pass

        if not signals:
            return {
                "score": 0,
                "classification": "CLEAN",
                "signals": [],
                "category": "clean",
                "sha256": self.calculate_sha256(file_path),
                "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                "signature_info": sig_info
            }

        raw_score = sum(s.points for s in signals)
        score = max(0, min(100, raw_score))
        classification = self._classify(score)

        if score >= 80:
            category = "confirmed_malware"
        elif score >= 60:
            category = "threat"
        elif score >= 40:
            category = "suspicious"
        elif is_junk:
            category = "junk"
        elif score >= 20:
            category = "low_risk"
        else:
            category = "clean"

        file_hash = self.calculate_sha256(file_path)

        return {
            "score": score,
            "classification": classification,
            "signals": signals,
            "category": category,
            "sha256": file_hash,
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "signature_info": sig_info
        }

    def _classify(self, score):
        if score >= 80:
            return "CONFIRMED_MALWARE"
        if score >= 60:
            return "THREAT"
        if score >= 40:
            return "SUSPICIOUS"
        if score >= 20:
            return "LOW_RISK"
        return "CLEAN"

    def _in_unusual_location(self, file_path):
        normal_script_homes = ("appdata", "program files", "program files (x86)", "programdata", "windows")
        lowered = file_path.lower()
        return not any(home in lowered for home in normal_script_homes)

    @staticmethod
    def format_explanation(result):
        """Generates a transparent, human-readable scoring breakdown."""
        lines = [
            f"Risk Score: {result['score']}/100",
            "",
            "Signals:"
        ]
        for s in result.get("signals", []):
            sign = "+" if s.points > 0 else ""
            lines.append(f"  {sign}{s.points} {s.reason}")
        lines.append("")
        lines.append(f"Classification: {result['classification']}")
        if result.get("sha256"):
            lines.append(f"SHA-256: {result['sha256'][:16]}...")
        return "\n".join(lines)
