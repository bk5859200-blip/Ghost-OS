import os
import sys
import json
import logging
from src.core.proc_utils import run_hidden

logger = logging.getLogger("ghost.intelligence.signature_verifier")


class SignatureVerifier:
    """
    Windows Authenticode digital signature and publisher verification engine.
    Extracts signature validity, signing certificate subject, and publisher info
    via silent hidden execution without console window flashing.
    Caches results in-memory to prevent repeated subprocess calls.
    """

    KNOWN_TRUSTED_PUBLISHERS = {
        "microsoft", "google", "apple", "mozilla", "python software foundation",
        "spotify", "valve", "electronic arts", "adobe", "discord", "zoom",
        "slack", "openai", "dell", "hp", "lenovo", "nvidia", "intel", "amd",
        "oracle", "cisco", "github", "jetbrains", "epic games", "ubisoft",
        "dropbox", "atlassian", "wireshark", "7-zip", "notepad++", "videolan"
    }

    def __init__(self):
        self._cache = {}  # (path, mtime, size) -> dict

    def verify(self, file_path: str) -> dict:
        """
        Verifies the digital signature of an executable or library.
        Returns a dict:
          - status: 'valid' | 'notsigned' | 'hashmismatch' | 'nottrusted' | 'unknown' | 'error'
          - valid: bool
          - publisher: str or None
          - subject: str
          - issuer: str
          - is_trusted_publisher: bool
        """
        if not file_path or not os.path.exists(file_path):
            return {
                "status": "unavailable",
                "valid": False,
                "publisher": None,
                "subject": "",
                "issuer": "",
                "is_trusted_publisher": False
            }

        # Check in-memory cache
        try:
            stat = os.stat(file_path)
            cache_key = (os.path.normpath(file_path).lower(), stat.st_mtime, stat.st_size)
            if cache_key in self._cache:
                return self._cache[cache_key]
        except OSError:
            cache_key = None

        if sys.platform != "win32":
            res = {
                "status": "unsupported_platform",
                "valid": False,
                "publisher": None,
                "subject": "",
                "issuer": "",
                "is_trusted_publisher": False
            }
            if cache_key:
                self._cache[cache_key] = res
            return res

        # Run hidden PowerShell Get-AuthenticodeSignature
        norm_path = os.path.abspath(file_path).replace("'", "''")
        ps_cmd = (
            f"$s = Get-AuthenticodeSignature -LiteralPath '{norm_path}'; "
            f"$sub = if ($s.SignerCertificate) {{ $s.SignerCertificate.Subject }} else {{ '' }}; "
            f"$iss = if ($s.SignerCertificate) {{ $s.SignerCertificate.Issuer }} else {{ '' }}; "
            f"[PSCustomObject]@{{ Status = $s.Status.ToString(); StatusMessage = $s.StatusMessage; Subject = $sub; Issuer = $iss }} | ConvertTo-Json -Compress"
        )

        try:
            cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd]
            proc = run_hidden(cmd, capture_output=True, text=True, timeout=12)

            if proc.returncode != 0 or not proc.stdout.strip():
                result = {
                    "status": "unknown",
                    "valid": False,
                    "publisher": None,
                    "subject": "",
                    "issuer": "",
                    "is_trusted_publisher": False
                }
            else:
                raw = json.loads(proc.stdout.strip())
                status = raw.get("Status", "").lower()
                subject = raw.get("Subject", "")
                issuer = raw.get("Issuer", "")

                # Extract Common Name (CN) or Organization (O) from subject
                publisher = None
                if subject:
                    for part in subject.split(","):
                        part = part.strip()
                        if part.startswith("CN="):
                            publisher = part[3:]
                            break
                        elif part.startswith("O=") and not publisher:
                            publisher = part[2:]
                    if not publisher:
                        publisher = subject

                is_valid = (status == "valid")
                is_trusted = False
                if is_valid and publisher:
                    low_pub = publisher.lower()
                    is_trusted = any(known in low_pub for known in self.KNOWN_TRUSTED_PUBLISHERS)

                result = {
                    "status": status,
                    "valid": is_valid,
                    "publisher": publisher,
                    "subject": subject,
                    "issuer": issuer,
                    "is_trusted_publisher": is_trusted
                }

        except Exception as e:
            logger.debug(f"Signature check failed for {file_path}: {e}")
            result = {
                "status": "error",
                "valid": False,
                "publisher": None,
                "subject": "",
                "issuer": "",
                "is_trusted_publisher": False,
                "error": str(e)
            }

        if cache_key:
            self._cache[cache_key] = result
        return result
