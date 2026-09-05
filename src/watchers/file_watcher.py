import os
import time
import threading
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import queue

logger = logging.getLogger("ghost.watchers.file_watcher")


class _GhostEventHandler(FileSystemEventHandler):
    """
    Handles file create/modify events with bounded queue and fixed worker pool.
    Prevents thread explosion under high file-event churn.
    """

    RELEVANT_EXTENSIONS = {
        ".exe", ".msi", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".hta", ".scr", ".com", ".pif", ".cpl", ".iso", ".zip"
    }

    def __init__(self, on_file_event, debounce_seconds=3, worker_count=2, max_queue_size=1000):
        super().__init__()
        self.on_file_event = on_file_event
        self.debounce_seconds = debounce_seconds
        self._queue = queue.Queue(maxsize=max_queue_size)
        self._pending_times = {}  # path -> timestamp when it becomes eligible
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._workers = []

        for i in range(worker_count):
            t = threading.Thread(target=self._worker_loop, name=f"file_watcher_worker_{i}", daemon=True)
            t.start()
            self._workers.append(t)

    def _is_relevant(self, path):
        if not path or os.path.isdir(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        # Also check for double extensions like .pdf.exe
        name = os.path.basename(path).lower()
        if any(name.endswith(sub) for sub in [".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".txt.exe", ".zip.exe"]):
            return True
        return ext in self.RELEVANT_EXTENSIONS

    def _schedule(self, path):
        if not self._is_relevant(path):
            return

        now = time.time()
        with self._lock:
            self._pending_times[path] = now + self.debounce_seconds

        try:
            self._queue.put_nowait(path)
        except queue.Full:
            logger.warning(f"File watcher queue full (max {self._queue.maxsize}) — dropping event for {path}")

    def _worker_loop(self):
        while not self._stop_event.is_set():
            try:
                path = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            # Check if debouncing wait is required
            with self._lock:
                target_time = self._pending_times.get(path)

            if target_time:
                wait_time = target_time - time.time()
                if wait_time > 0:
                    # Wait for debounce window (interruptible by stop)
                    if self._stop_event.wait(wait_time):
                        self._queue.task_done()
                        break

                # Verify this path wasn't re-scheduled for a later time by a newer event
                with self._lock:
                    latest_target = self._pending_times.get(path)
                    if latest_target and latest_target > target_time:
                        # Re-queued for later; skip processing this iteration
                        self._queue.task_done()
                        continue
                    self._pending_times.pop(path, None)

            if os.path.exists(path):
                try:
                    self.on_file_event(path)
                except Exception as e:
                    logger.error(f"Error handling file event for {path}: {e}")

            self._queue.task_done()

    def on_created(self, event):
        self._schedule(event.src_path)

    def on_modified(self, event):
        self._schedule(event.src_path)

    def on_moved(self, event):
        self._schedule(event.dest_path)

    def stop(self):
        self._stop_event.set()
        for t in self._workers:
            t.join(timeout=2.0)
        self._workers.clear()


class DesktopWatcher:
    """
    Watches designated folders (Downloads, Desktop, Documents, Temp, Startup)
    using event-driven OS hooks rather than recursive disk polling.
    """

    def __init__(self, watch_folders=None, on_file_event=None, debounce_seconds=3):
        self.raw_folders = watch_folders or self.default_watch_folders()
        self.on_file_event = on_file_event or (lambda p: None)
        self.debounce_seconds = debounce_seconds
        self.observer = None
        self.handler = None
        self._active_folders = []

    def start(self):
        """Starts the filesystem observer for all existing target folders."""
        self._active_folders = [f for f in self.raw_folders if os.path.exists(f)]
        if not self._active_folders:
            logger.warning("No valid watch folders found to monitor.")
            return

        self.handler = _GhostEventHandler(self.on_file_event, self.debounce_seconds)
        self.observer = Observer()
        for folder in self._active_folders:
            try:
                self.observer.schedule(self.handler, folder, recursive=False)
                logger.info(f"Watching folder: {folder}")
            except Exception as e:
                logger.warning(f"Failed to schedule watch on {folder}: {e}")

        self.observer.start()

    def stop(self):
        """Stops the observer thread and worker pool cleanly."""
        if self.handler:
            self.handler.stop()
            self.handler = None

        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=3)
            except Exception:
                pass
            self.observer = None

    @staticmethod
    def default_watch_folders():
        home = os.path.expanduser("~")
        appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        startup_dir = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        return [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents"),
            os.environ.get("TEMP", os.path.join(home, "AppData", "Local", "Temp")),
            startup_dir
        ]
