import subprocess
import sys


def run_hidden(cmd_args, **kwargs):
    """
    Executes subprocess.run with CREATE_NO_WINDOW on Windows.
    Prevents black CMD console flashes during background operations.
    """
    if sys.platform == "win32":
        flags = kwargs.get("creationflags", 0)
        flags |= subprocess.CREATE_NO_WINDOW
        kwargs["creationflags"] = flags
    return subprocess.run(cmd_args, **kwargs)


def popen_hidden(cmd_args, **kwargs):
    """
    Executes subprocess.Popen with CREATE_NO_WINDOW on Windows.
    """
    if sys.platform == "win32":
        flags = kwargs.get("creationflags", 0)
        flags |= subprocess.CREATE_NO_WINDOW
        kwargs["creationflags"] = flags
    return subprocess.Popen(cmd_args, **kwargs)
