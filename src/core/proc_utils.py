import subprocess
import sys


def _get_hidden_kwargs(kwargs):
    """
    Configures subprocess arguments for completely silent background execution on Windows.
    Applies CREATE_NO_WINDOW, STARTF_USESHOWWINDOW with SW_HIDE, and redirects stdin to DEVNULL
    to prevent visible CMD/console flashes.
    """
    kwargs = dict(kwargs)
    if sys.platform == "win32":
        flags = kwargs.get("creationflags", 0)
        flags |= subprocess.CREATE_NO_WINDOW
        kwargs["creationflags"] = flags

        si = kwargs.get("startupinfo")
        if si is None:
            si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = si

        if "stdin" not in kwargs:
            kwargs["stdin"] = subprocess.DEVNULL
    return kwargs


def run_hidden(cmd_args, **kwargs):
    """
    Executes subprocess.run without any visible console window on Windows.
    """
    return subprocess.run(cmd_args, **_get_hidden_kwargs(kwargs))


def popen_hidden(cmd_args, **kwargs):
    """
    Executes subprocess.Popen without any visible console window on Windows.
    """
    return subprocess.Popen(cmd_args, **_get_hidden_kwargs(kwargs))


def check_output_hidden(cmd_args, **kwargs):
    """
    Executes subprocess.check_output without any visible console window on Windows.
    """
    return subprocess.check_output(cmd_args, **_get_hidden_kwargs(kwargs))


def check_call_hidden(cmd_args, **kwargs):
    """
    Executes subprocess.check_call without any visible console window on Windows.
    """
    return subprocess.check_call(cmd_args, **_get_hidden_kwargs(kwargs))

