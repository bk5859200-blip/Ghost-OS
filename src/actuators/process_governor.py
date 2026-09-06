import sys
import psutil

class ProcessGovernor:
    """
    Manages process life cycles and schedules.
    Enables suspension, termination, and process niceness adjustments.
    """
    def __init__(self):
        # Mappings of standard OS priorities to psutil priority classes on Windows
        if sys.platform == "win32":
            self.priority_classes = {
                "IDLE": getattr(psutil, "IDLE_PRIORITY_CLASS", None),
                "BELOW_NORMAL": getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", None),
                "NORMAL": getattr(psutil, "NORMAL_PRIORITY_CLASS", None),
                "ABOVE_NORMAL": getattr(psutil, "ABOVE_NORMAL_PRIORITY_CLASS", None),
                "HIGH": getattr(psutil, "HIGH_PRIORITY_CLASS", None),
                "REALTIME": getattr(psutil, "REALTIME_PRIORITY_CLASS", None)
            }
        else:
            self.priority_classes = {
                "IDLE": 19,
                "BELOW_NORMAL": 10,
                "NORMAL": 0,
                "ABOVE_NORMAL": -5,
                "HIGH": -10,
                "REALTIME": -20
            }

    def terminate_process(self, pid):
        """Kills the process immediately."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            return False

    def suspend_process(self, pid):
        """Suspends process execution, releasing CPU without clearing its RAM contents."""
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def resume_process(self, pid):
        """Resumes a suspended process."""
        try:
            proc = psutil.Process(pid)
            proc.resume()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def set_priority(self, pid, priority_level="BELOW_NORMAL"):
        """
        Adjusts the CPU priority scheduling class of a target process.
        :param pid: Process Identifier
        :param priority_level: String representation of priority level
        """
        if priority_level not in self.priority_classes:
            return False
            
        try:
            proc = psutil.Process(pid)
            target_class = self.priority_classes[priority_level]
            proc.nice(target_class)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
