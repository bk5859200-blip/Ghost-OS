import os
import glob
import shutil
import subprocess
import logging
from src.core.proc_utils import run_hidden

logger = logging.getLogger("ghost.intelligence.defender_scanner")

# Default search candidates for MpCmdRun on Windows 10/11
DEFAULT_MPCMDRUN_PATHS = [
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"
]


def find_mpcmdrun(custom_path=None):
    """
    Dynamically locates the newest available MpCmdRun.exe on the system.
    Searches Windows Defender Platform directories first (most up-to-date),
    followed by Program Files and PATH.
    """
    if custom_path and os.path.exists(custom_path):
        return custom_path

    # Check Windows Defender Platform updates (e.g. C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\MpCmdRun.exe)
    platform_glob = r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    platform_matches = glob.glob(platform_glob)
    if platform_matches:
        # Sort descending so the latest platform version is chosen
        platform_matches.sort(reverse=True)
        for candidate in platform_matches:
            # Prefer 64-bit over X86 subdirectories if present
            if os.path.exists(candidate) and "\\x86\\" not in candidate.lower():
                return candidate
        if os.path.exists(platform_matches[0]):
            return platform_matches[0]

    # Standard Program Files paths
    for candidate in DEFAULT_MPCMDRUN_PATHS:
        if os.path.exists(candidate):
            return candidate

    # Check system PATH
    which_path = shutil.which("MpCmdRun.exe")
    if which_path and os.path.exists(which_path):
        return which_path

    return None


class DefenderScanner:
    """
    Wrapper around Windows Defender command-line scanning engine (MpCmdRun.exe).
    Automates on-demand scanning of newly-seen or suspicious files.
    Accurately differentiates between clean files, verified threats, scan errors,
    and timeouts — never treating a scanner error as a malware detection.
    """

    def __init__(self, mpcmdrun_path=None):
        self.mpcmdrun_path = find_mpcmdrun(mpcmdrun_path)
        self.available = bool(self.mpcmdrun_path and os.path.exists(self.mpcmdrun_path))
        if self.available:
            logger.info(f"Windows Defender CLI scanner located at: {self.mpcmdrun_path}")
        else:
            logger.warning("Windows Defender CLI scanner (MpCmdRun.exe) not found on system.")

    def is_available(self):
        """Returns True if the Defender command-line executable exists on disk."""
        return bool(self.mpcmdrun_path and os.path.exists(self.mpcmdrun_path))

    def scan_file(self, file_path, timeout_seconds=60):
        """
        Runs a targeted on-demand scan against a single file.
        Returns a dict:
          - scanned: bool
          - threat_found: bool
          - status: 'clean' | 'threat_detected' | 'scan_error' | 'timeout' | 'unavailable' | 'invalid_path'
          - detail: str
          - threat_name: str or None
        """
        if not self.is_available():
            return {
                "scanned": False,
                "threat_found": False,
                "status": "unavailable",
                "detail": "MpCmdRun.exe not found on this system.",
                "threat_name": None
            }

        abs_file_path = os.path.abspath(file_path)
        if not os.path.exists(abs_file_path):
            return {
                "scanned": False,
                "threat_found": False,
                "status": "invalid_path",
                "detail": "Target file no longer exists.",
                "threat_name": None
            }

        try:
            # -Scan -ScanType 3 = custom scan, -File targets a single path, -DisableRemediation ensures read-only check
            result = run_hidden(
                [self.mpcmdrun_path, "-Scan", "-ScanType", "3", "-File", abs_file_path, "-DisableRemediation"],
                capture_output=True,
                text=True,
                timeout=timeout_seconds
            )

            output = ((result.stdout or "") + (result.stderr or "")).strip()
            lowered = output.lower()

            # Exit Code 0: Scan finished, no threats found
            if result.returncode == 0:
                return {
                    "scanned": True,
                    "threat_found": False,
                    "status": "clean",
                    "detail": "No threats detected by Windows Defender.",
                    "threat_name": None
                }

            # If MpCmdRun reported an HRESULT error (e.g. 0x80070002 file not found, access denied)
            if "hr = 0x" in lowered or "error:" in lowered:
                return {
                    "scanned": False,
                    "threat_found": False,
                    "status": "scan_error",
                    "detail": f"Defender scan error: {output[-300:]}",
                    "threat_name": None
                }

            # Exit Code 2: Threat found
            if result.returncode == 2 or ("threat" in lowered and "found" in lowered and "no threats" not in lowered):
                # Extract threat name from output if present
                threat_name = "Threat detected"
                for line in output.splitlines():
                    if "threat" in line.lower() and ":" in line:
                        threat_name = line.strip()
                        break

                return {
                    "scanned": True,
                    "threat_found": True,
                    "status": "threat_detected",
                    "detail": threat_name or output[-300:],
                    "threat_name": threat_name
                }

            # Any other non-zero returncode without explicit threat text is a scan error (e.g. exit code 1, permission denied)
            return {
                "scanned": False,
                "threat_found": False,
                "status": "scan_error",
                "detail": f"Defender returned exit code {result.returncode}: {output[-300:] if output else 'unknown error'}",
                "threat_name": None
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"Defender scan timed out after {timeout_seconds}s for {file_path}")
            return {
                "scanned": False,
                "threat_found": False,
                "status": "timeout",
                "detail": f"Defender scan timed out after {timeout_seconds}s.",
                "threat_name": None
            }
        except Exception as e:
            logger.error(f"Defender scan exception for {file_path}: {e}")
            return {
                "scanned": False,
                "threat_found": False,
                "status": "scan_error",
                "detail": f"Defender execution error: {e}",
                "threat_name": None
            }
