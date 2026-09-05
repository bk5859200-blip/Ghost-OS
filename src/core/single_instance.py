import logging
import os
import sys

logger = logging.getLogger("ghost.core.single_instance")

MUTEX_NAME = "Local\\GhostOS_SingleInstance_Mutex"
ERROR_ALREADY_EXISTS = 183


class SingleInstance:
    """
    Prevents multiple Ghost OS processes from running at once using a Windows named mutex.
    If a duplicate instance launches, it detects the existing mutex and cleanly exits.
    """

    def __init__(self, mutex_name=MUTEX_NAME):
        self.mutex_name = mutex_name
        self.mutex_handle = None
        self.already_running = False

    def acquire(self):
        """
        Attempts to acquire the single-instance mutex.
        Returns True if this is the only running instance, False if another instance exists.
        """
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes

                kernel32 = ctypes.windll.kernel32
                kernel32.CreateMutexW.argtypes = [
                    wintypes.LPVOID,
                    wintypes.BOOL,
                    wintypes.LPCWSTR
                ]
                kernel32.CreateMutexW.restype = wintypes.HANDLE

                self.mutex_handle = kernel32.CreateMutexW(None, False, self.mutex_name)
                last_error = kernel32.GetLastError()

                if last_error == ERROR_ALREADY_EXISTS or not self.mutex_handle:
                    self.already_running = True
                    if self.mutex_handle:
                        kernel32.CloseHandle(self.mutex_handle)
                        self.mutex_handle = None
                    logger.warning("Another Ghost OS instance is already active. Exiting duplicate.")
                    return False
                return True
            except Exception as e:
                logger.warning(f"Windows single-instance mutex check failed: {e}")
                return True
        else:
            return True

    def release(self):
        """Releases the mutex handle on shutdown."""
        if self.mutex_handle and sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.CloseHandle(self.mutex_handle)
                self.mutex_handle = None
            except Exception:
                pass
