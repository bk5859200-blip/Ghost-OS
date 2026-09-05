import os
import time
import threading
import logging
import psutil

from src.database.db_manager import DBManager
from src.sensors.system_sensor import SystemSensor
from src.processes.process_monitor import ProcessMonitor
from src.actuators.ram_flusher import RAMFlusher
from src.actuators.process_governor import ProcessGovernor

from src.watchers.file_watcher import DesktopWatcher
from src.watchers.process_watcher import ProcessWatcher

from src.intelligence.threat_sentinel import ThreatSentinel
from src.intelligence.anomaly_detector import AnomalyDetector
from src.intelligence.defender_scanner import DefenderScanner

from src.decision.decision_engine import DecisionEngine, ASK_USER, NOTIFY, LOG, IGNORE, CRITICAL, HIGH, MEDIUM, LOW
from src.decision.safety_engine import SafetyEngine

from src.actions.cleaner import SystemCleaner
from src.actions.quarantine_manager import QuarantineManager
from src.actions.scan_job import ManualScanJob
from src.actions.diagnostics_job import DiagnosticsJob

from src.notifications.notifier import Notifier
from src.autostart.autostart_manager import sync_autostart_state

logger = logging.getLogger("ghost.core")


# Ghost Central States (Master Spec Section 8)
STATE_STARTING = "STARTING"
STATE_NORMAL = "NORMAL"
STATE_WATCHING = "WATCHING"
STATE_ATTENTION = "ATTENTION"
STATE_PROTECTING = "PROTECTING"
STATE_PAUSED = "PAUSED"
STATE_ERROR = "ERROR"
STATE_STOPPING = "STOPPING"


class GhostCore:
    """
    Supervises all guardian subsystems through a central state machine and unified event pipeline:
      EVENT -> NORMALIZE -> ANALYZE -> CLASSIFY -> DECIDE -> SAFETY CHECK -> ACT -> VERIFY -> NOTIFY -> REMEMBER
    """

    def __init__(self, config, db_mgr=None):
        self.config = config
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._health_state = STATE_STARTING
        self._threads = []
        self._process_pid = os.getpid()

        # Job locks to prevent duplicate concurrent tasks
        self._scan_lock = threading.Lock()
        self._cleanup_lock = threading.Lock()

        # Database & Memory
        self.db_mgr = db_mgr or DBManager()

        # Safety & Decision
        self.safety = SafetyEngine(config)
        self.decision = DecisionEngine()

        # Telemetry Sensors & Actuators
        self.sensor = SystemSensor()
        self.proc_monitor = ProcessMonitor()
        self.ram_flusher = RAMFlusher()
        self.proc_governor = ProcessGovernor()

        # Intelligence & Sentinels
        self.defender = DefenderScanner()
        self.threat_sentinel = ThreatSentinel(config, defender_scanner=self.defender)
        self.anomaly_detector = AnomalyDetector()

        # Actions & Quarantine
        self.cleaner = SystemCleaner(
            self.safety,
            db_mgr=self.db_mgr,
            require_confirmation=config.get("cleanup", {}).get("require_confirmation", True)
        )
        self.quarantine = QuarantineManager(db_mgr=self.db_mgr)

        # Notifications
        notif_cfg = config.get("notifications", {})
        self.notifier = Notifier(
            enabled=notif_cfg.get("enabled", True),
            cooldown_seconds=notif_cfg.get("cooldown_seconds", 120),
            aggregate_window_seconds=notif_cfg.get("aggregate_window_seconds", 300),
            db_mgr=self.db_mgr
        )

        # Watchers
        watch_folders = config.get("watch_folders", DesktopWatcher.default_watch_folders())
        self.file_watcher = DesktopWatcher(watch_folders, on_file_event=self._on_file_event)
        self.process_watcher = ProcessWatcher(
            on_process_started=self._on_process_started,
            on_process_ended=self._on_process_ended,
            poll_interval_seconds=config.get("monitoring", {}).get("process_interval_seconds", 5),
        )

        self._consecutive_cpu_violations = 0
        self._last_perf_log = 0

    @property
    def running(self):
        """Returns True if the core is running and not paused."""
        return not self._stop_event.is_set() and not self._pause_event.is_set()

    @running.setter
    def running(self, value):
        """Setter maintained for legacy test compatibility."""
        if value:
            self._stop_event.clear()
            self._pause_event.clear()
        else:
            self._pause_event.set()

    # ------------------------------------------------------------ Lifecycle
    def start(self):
        self._stop_event.clear()
        self._pause_event.clear()
        self._health_state = STATE_STARTING

        # Sync autostart configuration
        if "ghost" in self.config and "startup" in self.config["ghost"]:
            try:
                sync_autostart_state(self.config["ghost"]["startup"])
            except Exception as e:
                logger.warning(f"Failed to synchronize autostart state: {e}")

        # Spawn resilient worker loops
        self._spawn(self._system_monitor_loop, "system_monitor")
        self._spawn(lambda: self.process_watcher.run_loop(lambda: not self._pause_event.is_set()), "process_watcher")

        try:
            self.file_watcher.start()
            self._health_state = STATE_WATCHING
        except Exception as e:
            logger.error(f"File watcher failed to start: {e}")
            self._health_state = STATE_ERROR

        logger.info(f"Ghost Core started with state: {self._health_state}")
        self.notifier.notify_normal()

    def pause(self):
        self._pause_event.set()
        self._health_state = STATE_PAUSED
        logger.info("Ghost Core paused.")
        self.notifier.notify_paused()

    def resume(self):
        self._pause_event.clear()
        self._health_state = STATE_WATCHING
        logger.info("Ghost Core resumed.")
        self.notifier.notify_resumed()

    def stop(self):
        self._health_state = STATE_STOPPING
        self._stop_event.set()
        self.process_watcher.stop()
        try:
            self.file_watcher.stop()
        except Exception:
            pass

        # Join all spawned threads with timeout
        for t in list(self._threads):
            t.join(timeout=5.0)
            if t.is_alive():
                logger.warning(f"Thread '{t.name}' did not stop within 5.0s timeout")
        self._threads.clear()

        self._health_state = STATE_NORMAL
        logger.info("Ghost Core stopped.")

    def get_health_state(self):
        return self._health_state

    def set_health_state(self, state):
        self._health_state = state

    def _spawn(self, target, name):
        def supervisor():
            while not self._stop_event.is_set():
                try:
                    target()
                    break
                except Exception as e:
                    logger.error(f"Subsystem '{name}' encountered error: {e}", exc_info=True)
                    self._health_state = STATE_ERROR
                    self._stop_event.wait(3.0)

        t = threading.Thread(target=supervisor, daemon=True, name=name)
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------- System Monitor
    def _system_monitor_loop(self):
        poll_rate = self.config.get("monitoring", {}).get("system_interval_seconds", 2)
        retention_days = self.config.get("monitoring", {}).get("db_cleanup_days", 7)
        last_purge = 0

        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                self._stop_event.wait(poll_rate)
                continue

            try:
                metrics = self.sensor.collect_metrics()
                self.anomaly_detector.add_telemetry_sample(metrics)

                self.db_mgr.insert_system_metrics(
                    cpu=metrics["cpu_percent"],
                    ram=metrics["ram_percent"],
                    disk_pct=metrics["disk_used_percent"],
                    disk_read=metrics["disk_read_rate_mb"],
                    disk_write=metrics["disk_write_rate_mb"],
                    net_sent=metrics["net_sent_rate_mb"],
                    net_recv=metrics["net_recv_rate_mb"]
                )

                self._evaluate_telemetry(metrics)

                curr_time = time.time()
                if curr_time - self._last_perf_log > 60:
                    self._log_self_performance()
                    self._last_perf_log = curr_time

                if curr_time - last_purge > 6 * 3600:
                    self.db_mgr.purge_old_records(retention_days)
                    last_purge = curr_time

            except Exception as e:
                logger.error(f"System monitor tick failed: {e}")

            self._stop_event.wait(poll_rate)

    def _evaluate_telemetry(self, metrics):
        thresholds = self.config.get("thresholds", {})
        cpu_limit = thresholds.get("cpu", {}).get("critical_percent", 92.0)
        ticks_needed = thresholds.get("cpu", {}).get("consecutive_ticks", 3)
        mem_limit = thresholds.get("memory", {}).get("critical_percent", 95.0)

        if metrics["cpu_percent"] > cpu_limit:
            self._consecutive_cpu_violations += 1
        else:
            self._consecutive_cpu_violations = max(0, self._consecutive_cpu_violations - 1)

        persistent_cpu = self._consecutive_cpu_violations >= ticks_needed
        severity, outcome, reason = self.decision.decide_for_resource_anomaly(
            "CPU", metrics["cpu_percent"], cpu_limit, persistent=persistent_cpu
        )

        if outcome == NOTIFY:
            self._health_state = STATE_ATTENTION
            self.db_mgr.log_anomaly(
                source="system",
                entity_name="CPU",
                anomaly_type="cpu_sustained",
                score=metrics["cpu_percent"],
                description=reason
            )
            self._handle_cpu_mitigation()
            self.notifier.notify_info("Ghost OS", reason, signal_key="cpu_sustained", severity="MEDIUM")
            self._consecutive_cpu_violations = 0

        if metrics["ram_percent"] > mem_limit and self.config.get("automation", {}).get("auto_trim_memory", True):
            allowed, _ = self.safety.gate_action("trim_memory", "system-wide")
            if allowed:
                trimmed = self.ram_flusher.trim_all_user_processes()
                if trimmed:
                    self.notifier.notify_info("Ghost OS", f"High memory usage — trimmed working set for {trimmed} processes.", signal_key="ram_trim")

        # Stage B Baseline evaluation
        baseline_anomaly = self.anomaly_detector.evaluate_baseline(metrics)
        if baseline_anomaly:
            self.db_mgr.log_anomaly(
                source="system",
                entity_name=baseline_anomaly["feature"],
                anomaly_type="baseline_deviation",
                score=baseline_anomaly["z_score"],
                description=baseline_anomaly["description"]
            )

        # Stage C Isolation Forest evaluation
        vector = [
            metrics.get("cpu_percent", 0.0),
            metrics.get("ram_percent", 0.0),
            metrics.get("disk_used_percent", 0.0),
            metrics.get("disk_read_rate_mb", 0.0),
            metrics.get("disk_write_rate_mb", 0.0),
            metrics.get("net_sent_rate_mb", 0.0),
            metrics.get("net_recv_rate_mb", 0.0),
        ]
        is_iforest_anomaly, iforest_score = self.anomaly_detector.predict_anomaly(vector)
        if is_iforest_anomaly:
            self.db_mgr.log_anomaly(
                source="system",
                entity_name="MultiMetric",
                anomaly_type="isolation_forest",
                score=round(abs(iforest_score) * 100.0, 2),
                description=f"Multi-metric anomaly detected by Isolation Forest (score: {iforest_score:.3f})"
            )

    def _handle_cpu_mitigation(self):
        if not self.config.get("automation", {}).get("auto_lower_priority", True):
            return
        heavy_cpu, _ = self.proc_monitor.get_heavy_hitters(limit=2, cpu_threshold=40.0)
        for proc in heavy_cpu:
            allowed, _ = self.safety.gate_action("lower_priority", proc["name"], is_process=True)
            if allowed:
                self.proc_governor.set_priority(proc["pid"], "BELOW_NORMAL")

    def _log_self_performance(self):
        try:
            p = psutil.Process(self._process_pid)
            mem_mb = p.memory_info().rss / (1024 * 1024)
            cpu_pct = p.cpu_percent(interval=None)
            logger.debug(f"[Ghost OS Telemetry] Memory: {mem_mb:.2f} MB | CPU: {cpu_pct:.1f}%")
        except Exception:
            pass

    # ------------------------------------------------------------- Process Events
    def _on_process_started(self, proc):
        logger.debug(f"New process: {proc['name']} (pid={proc['pid']})")

        is_suspicious_spawn, spawn_reason = self.proc_monitor.check_spawn_anomaly(proc)
        anomaly_flag = 1 if is_suspicious_spawn else 0

        self.db_mgr.log_process_event(
            event_type="started",
            pid=proc["pid"],
            name=proc["name"],
            exe_path=proc.get("exe_path"),
            parent_pid=proc.get("parent_pid"),
            parent_name=proc.get("parent_name"),
            cpu_percent=proc.get("cpu_percent", 0.0),
            memory_rss_mb=proc.get("memory_rss_mb", 0.0),
            anomaly_flag=anomaly_flag
        )

        if is_suspicious_spawn:
            self._health_state = STATE_ATTENTION
            self.db_mgr.log_anomaly(
                source="process",
                entity_name=proc["name"],
                anomaly_type="suspicious_spawn",
                score=75.0,
                description=spawn_reason,
                details=proc
            )
            self.notifier.notify_info("⚠ Ghost OS", spawn_reason, signal_key=f"spawn:{proc['pid']}", severity="HIGH")

    def _on_process_ended(self, proc):
        logger.debug(f"Process ended: {proc['name']} (pid={proc['pid']})")
        self.db_mgr.log_process_event(
            event_type="ended",
            pid=proc["pid"],
            name=proc["name"]
        )

    # ---------------------------------------------------------------- Unified Event Pipeline
    def execute_event_pipeline(self, file_path):
        """
        Unified Event Processing Pipeline:
          1. NORMALIZE
          2. ANALYZE
          3. CLASSIFY
          4. DECIDE
          5. SAFETY CHECK
          6. ACT (if confirmed / configured)
          7. VERIFY
          8. NOTIFY
          9. REMEMBER
        """
        # 1. NORMALIZE
        norm_path = os.path.normpath(file_path)
        if not os.path.exists(norm_path):
            return {"status": "skipped", "reason": "nonexistent"}

        # 2. ANALYZE
        analysis = self.threat_sentinel.analyze_file(norm_path)
        if not analysis:
            return {"status": "skipped", "reason": "no_analysis"}

        # 3. CLASSIFY
        score = analysis["risk_score"]
        classification = analysis["classification"]
        signals = analysis["signals"]
        category = analysis["category"]

        # 4. DECIDE
        severity, outcome, decision_reason = self.decision.decide_for_file_risk(analysis)

        if outcome in (IGNORE, LOG) or not signals:
            return {"status": "logged", "severity": severity, "score": score}

        # 5. SAFETY CHECK
        detector = "defender" if analysis.get("threat_confirmed") else "threat_sentinel"
        reason = "; ".join(s["reason"] for s in signals)

        # 9. REMEMBER (Guardian Event in DB)
        event_id = self.db_mgr.log_guardian_event(
            file_path=norm_path,
            detector=detector,
            reason=reason,
            severity=classification,
            risk_score=score,
            signals=signals
        )

        # 6. ACT & 7. VERIFY & 8. NOTIFY
        if classification in (CRITICAL, HIGH):
            self._health_state = STATE_PROTECTING
            self.notifier.alert_detection(
                event_id=event_id,
                file_path=norm_path,
                reason=reason,
                severity=classification,
                on_response=self._handle_user_response
            )
        elif classification == MEDIUM:
            self._health_state = STATE_ATTENTION
            self.notifier.notify_suspicious(
                file_path=norm_path,
                risk_score=score,
                classification=classification,
                reason=reason
            )

        return {
            "status": "processed",
            "event_id": event_id,
            "severity": classification,
            "score": score,
            "outcome": outcome
        }

    def _on_file_event(self, file_path):
        if not self.running:
            return
        try:
            self.execute_event_pipeline(file_path)
        except Exception as e:
            logger.error(f"File event handling pipeline failed for {file_path}: {e}")

    def _handle_user_response(self, event_id, file_path, action):
        if action == "quarantine":
            allowed, _ = self.safety.gate_action("quarantine", file_path)
            if allowed:
                success, dest, _ = self.quarantine.quarantine_file(event_id, file_path)
                if success:
                    self.notifier.notify_quarantined(file_path, 80)
        elif action == "delete":
            allowed, _ = self.safety.gate_action("delete", file_path)
            if allowed:
                self.quarantine.delete_file(event_id, file_path)
        else:
            self.quarantine.ignore_event(event_id)

    # ------------------------------------------------------------- Quick Scan
    def run_quick_scan(self):
        """Scans all configured watch folders on-demand and reports results."""
        if not self._scan_lock.acquire(blocking=False):
            logger.warning("Quick scan request rejected: a scan is already in progress.")
            self.notifier.notify_info(
                "Ghost OS",
                "A system scan is already in progress.",
                signal_key="scan_running"
            )
            return

        try:
            logger.info("Quick scan started.")
            scanned_count = 0
            flagged_count = 0

            for folder in self.file_watcher.raw_folders:
                if not os.path.exists(folder):
                    continue
                try:
                    for item in os.listdir(folder):
                        item_path = os.path.join(folder, item)
                        if os.path.isfile(item_path):
                            scanned_count += 1
                            analysis = self.threat_sentinel.analyze_file(item_path)
                            if analysis and analysis["risk_score"] >= 60:
                                flagged_count += 1
                                self._on_file_event(item_path)
                except OSError:
                    continue

            if flagged_count == 0:
                self.notifier.notify_info(
                    "Ghost OS — Quick Scan",
                    f"Scanned {scanned_count} files across watch folders.\nNo threats or high-risk files found.",
                    signal_key="quick_scan"
                )
            else:
                self.notifier.notify_info(
                    "⚠ Ghost OS — Quick Scan",
                    f"Scanned {scanned_count} files.\n{flagged_count} item(s) flagged for review.",
                    signal_key="quick_scan",
                    severity="HIGH"
                )
        finally:
            self._scan_lock.release()

    # ----------------------------------------------------------- Cleanup
    def propose_cleanup(self):
        if self._cleanup_lock.locked():
            logger.warning("Cleanup proposal rejected: a cleanup operation is already in progress.")
            self.notifier.notify_info(
                "Ghost OS",
                "A cleanup operation is already in progress.",
                signal_key="cleanup_running"
            )
            return

        preview = self.cleaner.preview()
        if preview["count"] == 0:
            self.notifier.notify_info("Ghost OS", "Temporary folders are already clean. No action needed.", signal_key="clean_empty")
            return

        if self.config.get("cleanup", {}).get("require_confirmation", True):
            self.notifier.notify_cleanup_proposal(
                preview["count"],
                preview["size_mb"],
                on_review=lambda: self._run_cleanup(preview["candidates"]),
                on_later=lambda: None
            )
        else:
            self._run_cleanup(preview["candidates"])

    def _run_cleanup(self, candidates):
        def worker():
            if not self._cleanup_lock.acquire(blocking=False):
                logger.warning("Cleanup execution rejected: a cleanup operation is already in progress.")
                return
            try:
                result = self.cleaner.execute(candidates)
                self.notifier.notify_cleanup_complete(
                    result["files_removed"] + result["dirs_removed"],
                    result["space_recovered_mb"]
                )
            finally:
                self._cleanup_lock.release()

        t = threading.Thread(target=worker, name="ghost_cleanup_worker", daemon=True)
        t.start()

    # ------------------------------------------------------------- Diagnostics & Scans
    def create_manual_scan(self, on_progress=None, on_complete=None):
        """Creates a finite manual scan job across configured watch folders."""
        folders = getattr(self.file_watcher, "raw_folders", self.config.get("watch_folders", []))
        return ManualScanJob(
            watch_folders=folders,
            threat_sentinel=self.threat_sentinel,
            on_progress=on_progress,
            on_complete=on_complete
        )

    def run_diagnostics(self):
        """Runs the diagnostic health checklist and returns structured results."""
        job = DiagnosticsJob(config=self.config, db_mgr=self.db_mgr)
        return job.run_all_checks()

    # ------------------------------------------------------------- Memory & Digest
    def get_away_summary(self, window_hours=4):
        return self.db_mgr.get_away_summary(window_hours=window_hours)
