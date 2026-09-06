import os
import time
import logging
import threading

from src.decision.decision_engine import DecisionEngine, ASK_USER, NOTIFY

logger = logging.getLogger("ghost.actions.scan_job")


STATE_PENDING = "PENDING"
STATE_RUNNING = "RUNNING"
STATE_COMPLETED = "COMPLETED"
STATE_FAILED = "FAILED"
STATE_CANCELLED = "CANCELLED"


class ManualScanJob:
    """
    Finite manual scan job for Ghost OS watch folders.
    Computes upfront file list, provides progress callbacks, tracks flagged items,
    and runs asynchronously without blocking the main event loop.
    """

    def __init__(self, watch_folders, threat_sentinel, on_progress=None, on_complete=None, decision_engine=None):
        self.job_id = f"scan_{int(time.time() * 1000)}"
        self.watch_folders = list(watch_folders)
        self.threat_sentinel = threat_sentinel
        self.decision_engine = decision_engine or DecisionEngine()
        self.on_progress = on_progress
        self.on_complete = on_complete

        self._stop_event = threading.Event()
        self._thread = None

        self.state = STATE_PENDING
        self.is_running = False
        self.completed = False
        self.total_files = 0
        self.scanned_count = 0
        self.current_operation = "Pending"
        self.flagged_items = []
        self.start_time = None
        self.end_time = None
        self.error = None
        self.result = None

    def _collect_files(self):
        """Discovers all candidate files across watch folders upfront."""
        files = []
        for folder in self.watch_folders:
            if not os.path.exists(folder):
                continue
            try:
                for root, _, filenames in os.walk(folder):
                    for fname in filenames:
                        files.append(os.path.join(root, fname))
            except Exception as e:
                logger.warning(f"Error scanning folder '{folder}': {e}")
        return files

    def start(self):
        """Starts the manual scan on a background daemon thread."""
        if self.is_running:
            logger.warning("Scan job is already running.")
            return False

        self._stop_event.clear()
        self.is_running = True
        self.state = STATE_RUNNING
        self.completed = False
        self.flagged_items = []
        self.scanned_count = 0
        self.current_operation = "Initializing file list..."
        self.start_time = time.time()
        self.end_time = None
        self.error = None
        self.result = None

        self._thread = threading.Thread(target=self._run, name=f"ghost_scan_{self.job_id}", daemon=True)
        self._thread.start()
        return True

    def cancel(self):
        """Cancels an active scan job."""
        if self.is_running:
            self._stop_event.set()
            self.current_operation = "Cancelling..."
            logger.info(f"Scan job {self.job_id} cancellation requested.")

    def join(self, timeout=None):
        """Waits for the scan thread to finish."""
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def progress_pct(self):
        if self.total_files == 0:
            return 100.0 if self.completed else 0.0
        return round((self.scanned_count / self.total_files) * 100.0, 1)

    def _run(self):
        try:
            self.current_operation = "Discovering files..."
            candidate_files = self._collect_files()
            self.total_files = len(candidate_files)
            logger.info(f"Manual scan [{self.job_id}] starting: {self.total_files} file(s) across {len(self.watch_folders)} folder(s).")

            for idx, file_path in enumerate(candidate_files, start=1):
                if self._stop_event.is_set():
                    self.state = STATE_CANCELLED
                    self.current_operation = "Cancelled"
                    logger.info(f"Scan job [{self.job_id}] interrupted by stop event.")
                    break

                self.current_operation = f"Scanning: {os.path.basename(file_path)}"
                if self.on_progress:
                    try:
                        self.on_progress(self.scanned_count, self.total_files, file_path)
                    except Exception as pe:
                        logger.debug(f"Scan on_progress callback error: {pe}")

                if os.path.isfile(file_path):
                    try:
                        analysis = self.threat_sentinel.analyze_file(file_path)
                        if analysis:
                            severity, outcome, reason = self.decision_engine.decide_for_file_risk(analysis)
                            if outcome in (ASK_USER, NOTIFY):
                                self.flagged_items.append({
                                    "file_path": file_path,
                                    "risk_score": analysis.get("risk_score", 0),
                                    "classification": severity,
                                    "category": analysis.get("category", "unknown"),
                                    "outcome": outcome,
                                    "reason": reason,
                                    "signals": analysis.get("signals", [])
                                })
                    except Exception as fe:
                        logger.debug(f"Error analyzing '{file_path}': {fe}")

                self.scanned_count = idx

            if not self._stop_event.is_set():
                self.completed = True
                self.state = STATE_COMPLETED
                self.current_operation = "Completed"
        except Exception as e:
            self.error = str(e)
            self.state = STATE_FAILED
            self.current_operation = f"Failed: {e}"
            logger.error(f"Manual scan job [{self.job_id}] failed: {e}", exc_info=True)
        finally:
            self.is_running = False
            self.end_time = time.time()

            result = {
                "job_id": self.job_id,
                "state": self.state,
                "completed": self.completed,
                "total_files": self.total_files,
                "scanned_count": self.scanned_count,
                "flagged_count": len(self.flagged_items),
                "flagged_items": self.flagged_items,
                "duration_seconds": round((self.end_time or time.time()) - (self.start_time or time.time()), 2),
                "error": self.error
            }
            self.result = result

            if self.on_complete:
                try:
                    self.on_complete(result)
                except Exception as ce:
                    logger.debug(f"Scan on_complete callback error: {ce}")
