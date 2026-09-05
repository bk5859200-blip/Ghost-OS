"""
Registers Ghost OS to launch automatically when Windows starts.

Two approaches are supported:

1. register_registry_run() — RECOMMENDED DEFAULT. Adds a HKCU Run key entry.
   No admin needed to install, and Ghost runs at your normal user privilege
   level. Per least-privilege principles, this is the default.

2. register_task_scheduler() — OPTIONAL, elevated alternative for Task Scheduler.
"""

import os
import subprocess
import sys
from src.core.path_manager import PathManager
from src.core.proc_utils import run_hidden

APP_NAME = "GhostOS"
TASK_NAME = "GhostOSGuardian"
REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _pythonw_launch_command():
    """Returns (pythonw_exe, script_path) tuple for starting in source mode."""
    python_exe = sys.executable
    if "pythonw.exe" in python_exe.lower():
        pythonw_exe = python_exe
    else:
        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
        if not os.path.exists(pythonw_exe):
            pythonw_exe = python_exe

    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ghost_os_main.py"))
    return pythonw_exe, script_path


def _launch_command():
    """Resolves launch command for registry Run entry (packaged EXE or pythonw.exe)."""
    if PathManager.is_packaged():
        return f'"{sys.executable}"'

    pythonw_exe, script_path = _pythonw_launch_command()
    return f'"{pythonw_exe}" "{script_path}"'


def register_registry_run():
    """Adds a HKCU Run key entry. No admin required to install."""
    try:
        import winreg
        command = _launch_command()

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_RUN_KEY,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
        winreg.CloseKey(key)
        return True, command
    except Exception as e:
        return False, str(e)


def unregister_registry_run():
    """Removes the HKCU Run key entry."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_RUN_KEY,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return True
    except Exception:
        return False


def is_registered_registry_run():
    """Checks whether Ghost OS is currently set to run on startup in HKCU."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_RUN_KEY,
            0,
            winreg.KEY_READ
        )
        value, _ = winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return bool(value)
    except (FileNotFoundError, OSError, ImportError):
        return False


def sync_autostart_state(should_be_enabled: bool):
    """Ensures autostart state matches policy configuration."""
    is_enabled = is_registered_registry_run()
    if should_be_enabled and not is_enabled:
        register_registry_run()
    elif not should_be_enabled and is_enabled:
        unregister_registry_run()


def register_task_scheduler():
    command = _launch_command()
    cmd = [
        "schtasks", "/Create", "/TN", TASK_NAME,
        "/TR", command,
        "/SC", "ONLOGON",
        "/RL", "HIGHEST",
        "/F"
    ]
    result = run_hidden(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout + result.stderr


def unregister_task_scheduler():
    cmd = ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]
    result = run_hidden(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout + result.stderr


def is_registered_task_scheduler():
    cmd = ["schtasks", "/Query", "/TN", TASK_NAME]
    result = run_hidden(cmd, capture_output=True, text=True)
    return result.returncode == 0


if __name__ == "__main__":
    success, command = register_registry_run()
    print(f"Registered (unprivileged, HKCU Run key): {command} (status={success})")
