import psutil

class ProcessGovernor:
    """
    Manages process life cycles and schedules.
    Enables suspension, termination, and process niceness adjustments.
    """
    def __init__(self):
        # Mappings of standard OS priorities to psutil priority classes on Windows
        self.priority_classes = {
            "IDLE": psutil.IDLE_PRIORITY_CLASS,
            "BELOW_NORMAL": psutil.BELOW_NORMAL_PRIORITY_CLASS,
            "NORMAL": psutil.NORMAL_PRIORITY_CLASS,
            "ABOVE_NORMAL": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
            "HIGH": psutil.HIGH_PRIORITY_CLASS,
            "REALTIME": psutil.REALTIME_PRIORITY_CLASS
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
