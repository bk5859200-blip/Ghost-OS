import os
import logging

logger = logging.getLogger("ghost.decision.safety_engine")


class SafetyEngine:
    """
    Final security gate before any action on files or processes.
    Enforces protected system paths, protected processes, path traversal prevention,
    and strict dry-run behavior.
    """

    DEFAULT_PROTECTED_PROCESSES = {
        "explorer.exe", "winlogon.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "smss.exe", "msmpeng.exe",
        "securityhealthservice.exe", "python.exe", "pythonw.exe",
        "cmd.exe", "powershell.exe", "taskmgr.exe", "dwm.exe",
        "svchost.exe", "spoolsv.exe", "conhost.exe"
    }

    def __init__(self, config=None):
        cfg = config or {}
        security_cfg = cfg.get("security", {})

        config_procs = {p.lower() for p in security_cfg.get("protected_processes", [])}
        self.protected_processes = self.DEFAULT_PROTECTED_PROCESSES | config_procs

        # Expand paths (guarantee core system and user media directories are always protected)
        raw_paths = security_cfg.get("protected_paths", [])
        core_paths = [
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "%USERPROFILE%\\Documents",
            "%USERPROFILE%\\Pictures",
            "%USERPROFILE%\\Videos"
        ]
        all_raw = list(set(raw_paths + core_paths))
        self.protected_paths = [
            os.path.normpath(os.path.expandvars(p)).lower()
            for p in all_raw
        ]

        self.dry_run = cfg.get("safety", {}).get("dry_run", True)

    def is_process_protected(self, process_name):
        return (process_name or "").lower() in self.protected_processes

    def is_path_protected(self, file_path):
        normalized = os.path.normpath(os.path.realpath(file_path)).lower()
        for protected in self.protected_paths:
            if normalized == protected or normalized.startswith(protected + os.sep):
                return True
        return False

    def can_act_on_process(self, process_name, pid=None):
        if self.is_process_protected(process_name):
            logger.info(f"Blocked action on protected process: {process_name} (pid={pid})")
            return False
        return True

    def can_act_on_file(self, file_path):
        if not os.path.exists(file_path):
            logger.info(f"Blocked action on nonexistent file: {file_path}")
            return False
        if self.is_path_protected(file_path):
            logger.info(f"Blocked action on protected path: {file_path}")
            return False
        return True

    def validate_path(self, file_path, allowed_roots):
        """
        Prevents path traversal and symlink escapes.
        Ensures real target file is strictly inside one of allowed_roots.
        """
        try:
            real_target = os.path.realpath(file_path)
        except Exception:
            return False

        for root in allowed_roots:
            try:
                real_root = os.path.realpath(root)
                if os.path.commonpath([real_target, real_root]) == real_root:
                    return True
            except Exception:
                continue
        return False

    def gate_action(self, action_type, target, is_process=False):
        """
        Single entry point for actuators: returns (allowed: bool, reason: str).
        When dry_run is active, logs the proposed action and returns (False, 'dry_run').
        """
        if is_process:
            allowed = self.can_act_on_process(target)
        else:
            allowed = self.can_act_on_file(target)

        if not allowed:
            return False, "blocked_by_safety_policy"

        if self.dry_run:
            logger.info(f"[DRY RUN] Would perform '{action_type}' on '{target}' — no changes made.")
            return False, "dry_run"

        return True, "allowed"
