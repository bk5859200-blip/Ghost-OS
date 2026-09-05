import threading
import time
import logging
from src.processes.process_monitor import ProcessMonitor

logger = logging.getLogger("ghost.watchers.process_watcher")


class ProcessWatcher:
    """
    Diffs successive process snapshots to emit creation/termination events,
    with parent-child relationship tracking and spawn anomaly checks.
    """

    def __init__(self, on_process_started=None, on_process_ended=None, poll_interval_seconds=5):
        self.monitor = ProcessMonitor()
        self.on_process_started = on_process_started or (lambda p: None)
        self.on_process_ended = on_process_ended or (lambda p: None)
        self.poll_interval = poll_interval_seconds
        self._known_pids = {}
        self._stop_event = threading.Event()

    def _snapshot(self):
        processes = self.monitor.get_running_processes()
        return {p["pid"]: p for p in processes}

    def prime(self):
        """Captures initial process tree without reporting initial processes as new."""
        self._known_pids = self._snapshot()

    def poll_once(self):
        current = self._snapshot()
        current_pids = set(current.keys())
        known_pids = set(self._known_pids.keys())

        for new_pid in current_pids - known_pids:
            proc_dict = current[new_pid]
            self.monitor.record_process_start(proc_dict)
            self.on_process_started(proc_dict)

        for ended_pid in known_pids - current_pids:
            self.on_process_ended(self._known_pids[ended_pid])

        self._known_pids = current

    def run_loop(self, should_continue=None):
        self.prime()
        self._stop_event.clear()
        while not self._stop_event.is_set():
            if should_continue is None or should_continue():
                try:
                    self.poll_once()
                except Exception as e:
                    logger.warning(f"Process watcher tick failed: {e}")
            self._stop_event.wait(self.poll_interval)

    def stop(self):
        self._stop_event.set()
