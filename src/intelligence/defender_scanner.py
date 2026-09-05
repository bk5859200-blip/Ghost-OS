import os
import subprocess
from src.core.proc_utils import run_hidden

# Standard install location for Defender's command-line scanner on Windows 10/11.
DEFAULT_MPCMDRUN_PATH = (
    r"C:\Program Files\Windows Defender\MpCmdRun.exe"
)


class DefenderScanner:
    """
    Thin wrapper around Windows Defender's own scanning engine (MpCmdRun.exe).
    Ghost OS deliberately does NOT try to reimplement malware signature detection —
    that's a losing game against a dedicated AV engine that gets daily definition
    updates. Instead, this automates Defender against newly-seen files and lets
    Ghost OS layer alerting + quarantine UX on top of a real detection engine.
    """

    def __init__(self, mpcmdrun_path=None):
        self.mpcmdrun_path = mpcmdrun_path or DEFAULT_MPCMDRUN_PATH
        self.available = os.path.exists(self.mpcmdrun_path)

    def is_available(self):
        """Returns True if the Defender command-line executable exists on disk."""
        return os.path.exists(self.mpcmdrun_path)

    def scan_file(self, file_path, timeout_seconds=60):
        """
        Runs a targeted on-demand scan against a single file.
        :return: dict {scanned: bool, threat_found: bool, detail: str}
        """
        if not self.available:
            return {"scanned": False, "threat_found": False, "detail": "MpCmdRun.exe not found on this system."}

        if not os.path.exists(file_path):
            return {"scanned": False, "threat_found": False, "detail": "File no longer exists."}

        try:
            # -Scan -ScanType 3 = custom scan, -File targets a single path
            result = run_hidden(
                [self.mpcmdrun_path, "-Scan", "-ScanType", "3", "-File", file_path, "-DisableRemediation"],
                capture_output=True,
                text=True,
                timeout=timeout_seconds
            )

            output = (result.stdout or "") + (result.stderr or "")

            # MpCmdRun exits 0 when nothing found, non-zero (commonly 2) when a threat is detected.
            # We also sanity-check the text output since exit codes alone can be ambiguous
            # across Defender builds.
            threat_found = result.returncode != 0 or "found" in output.lower() and "threat" in output.lower()

            return {
                "scanned": True,
                "threat_found": threat_found,
                "detail": output.strip()[-500:]  # tail of output is usually the verdict
            }
        except subprocess.TimeoutExpired:
            return {"scanned": False, "threat_found": False, "detail": "Scan timed out."}
        except Exception as e:
            return {"scanned": False, "threat_found": False, "detail": f"Scan error: {e}"}
