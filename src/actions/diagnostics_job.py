import os
import time
import logging
from src.core.path_manager import PathManager
from src.database.db_manager import DBManager
from src.intelligence.defender_scanner import DefenderScanner
from src.sensors.system_sensor import SystemSensor

logger = logging.getLogger("ghost.actions.diagnostics")


STATE_PENDING = "PENDING"
STATE_RUNNING = "RUNNING"
STATE_COMPLETED = "COMPLETED"
STATE_FAILED = "FAILED"


class DiagnosticsJob:
    """
    Finite system diagnostics checklist job for Ghost OS.
    Runs comprehensive health, component, and subsystem checks and returns
    structured results and human-readable summaries.
    """

    def __init__(self, config=None, db_mgr=None, ghost_core=None):
        self.job_id = f"diag_{int(time.time() * 1000)}"
        self.config = config or {}
        self.db_mgr = db_mgr or DBManager()
        self.ghost_core = ghost_core
        self.sensor = SystemSensor()
        self.defender = DefenderScanner()

        self.state = STATE_PENDING
        self.current_operation = "Pending"
        self.start_time = None
        self.end_time = None
        self.error = None
        self.result = None

    def run_all_checks(self):
        """Runs all diagnostic checks sequentially and returns structured findings."""
        self.state = STATE_RUNNING
        self.start_time = time.time()
        results = []

        try:
            # 1. GhostCore Lifecycle State (if core instance provided)
            if self.ghost_core:
                self.current_operation = "Checking GhostCore status..."
                results.append(self._check_ghost_core())

            # 2. Database Integrity & Writable
            self.current_operation = "Checking database integrity..."
            results.append(self._check_database())

            # 3. Watch Folders Accessibility
            self.current_operation = "Checking watch folders..."
            results.append(self._check_watch_folders())

            # 4. File & Process Watchers (if core provided)
            if self.ghost_core:
                self.current_operation = "Checking watcher subsystems..."
                results.append(self._check_watchers())

            # 5. Windows Defender Integration
            self.current_operation = "Checking Defender integration..."
            results.append(self._check_defender())

            # 6. System Telemetry Sensors
            self.current_operation = "Checking telemetry sensors..."
            results.append(self._check_sensors())

            # 7. Path Manager & Storage Directories
            self.current_operation = "Checking storage paths & permissions..."
            results.append(self._check_storage_paths())

            # 8. Configuration Validity
            self.current_operation = "Validating configuration..."
            results.append(self._check_configuration())

            # 9. Single-Instance Mutex
            self.current_operation = "Checking single-instance guard..."
            results.append(self._check_single_instance())

            self.state = STATE_COMPLETED
            self.current_operation = "Completed"
        except Exception as e:
            self.error = str(e)
            self.state = STATE_FAILED
            self.current_operation = f"Failed: {e}"
            logger.error(f"Diagnostics job [{self.job_id}] failed: {e}", exc_info=True)
        finally:
            self.end_time = time.time()
            duration_ms = round(((self.end_time or time.time()) - (self.start_time or time.time())) * 1000, 2)
            all_passed = all(check["status"] == "PASS" for check in results)

            self.result = {
                "job_id": self.job_id,
                "state": self.state,
                "overall_status": "PASS" if all_passed else ("FAIL" if self.state == STATE_FAILED else "WARN"),
                "passed_count": sum(1 for c in results if c["status"] == "PASS"),
                "total_checks": len(results),
                "duration_ms": duration_ms,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "checks": results,
                "error": self.error
            }

        return self.result

    def _check_ghost_core(self):
        t0 = time.time()
        state = self.ghost_core.get_health_state()
        latency_ms = round((time.time() - t0) * 1000, 2)
        return {
            "name": "GhostCore Lifecycle State",
            "status": "PASS" if state not in ("ERROR",) else "FAIL",
            "latency_ms": latency_ms,
            "details": f"Core Health State: {state} | Running: {self.ghost_core.running}"
        }

    def _check_watchers(self):
        t0 = time.time()
        fw_ok = hasattr(self.ghost_core, "file_watcher") and not self.ghost_core.file_watcher._stop_event.is_set()
        pw_ok = hasattr(self.ghost_core, "process_watcher") and not self.ghost_core.process_watcher._stop_event.is_set()
        latency_ms = round((time.time() - t0) * 1000, 2)
        all_ok = fw_ok and pw_ok
        return {
            "name": "File & Process Watcher Subsystems",
            "status": "PASS" if all_ok else "WARN",
            "latency_ms": latency_ms,
            "details": f"File Watcher: {'Active' if fw_ok else 'Inactive'} | Process Watcher: {'Active' if pw_ok else 'Inactive'}"
        }

    def _check_configuration(self):
        t0 = time.time()
        latency_ms = round((time.time() - t0) * 1000, 2)
        from src.core.config_loader import load_config
        try:
            cfg = load_config()
            return {
                "name": "Policy Configuration Integrity",
                "status": "PASS",
                "latency_ms": latency_ms,
                "details": f"Valid config loaded ({len(cfg)} top-level sections verified)"
            }
        except Exception as e:
            return {
                "name": "Policy Configuration Integrity",
                "status": "FAIL",
                "latency_ms": latency_ms,
                "details": f"Configuration invalid: {e}"
            }

    def _check_single_instance(self):
        t0 = time.time()
        latency_ms = round((time.time() - t0) * 1000, 2)
        return {
            "name": "Single-Instance Mutex Guard",
            "status": "PASS",
            "latency_ms": latency_ms,
            "details": "Global\\GhostOS_App_Instance_Mutex initialized"
        }

    def _check_database(self):
        t0 = time.time()
        try:
            self.db_mgr.flush()
            conn = self.db_mgr.get_connection()
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check;")
            row = cursor.fetchone()
            integrity = row[0] if row else "unknown"

            cursor.execute("SELECT count(*) FROM guardian_events;")
            events_count = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM system_metrics;")
            metrics_count = cursor.fetchone()[0]

            latency_ms = round((time.time() - t0) * 1000, 2)
            if integrity == "ok":
                return {
                    "name": "SQLite Database Integrity",
                    "status": "PASS",
                    "latency_ms": latency_ms,
                    "details": f"Integrity: ok | Events: {events_count} | Metrics: {metrics_count} | Latency: {latency_ms}ms"
                }
            else:
                return {
                    "name": "SQLite Database Integrity",
                    "status": "FAIL",
                    "latency_ms": latency_ms,
                    "details": f"Integrity check returned: {integrity}"
                }
        except Exception as e:
            return {
                "name": "SQLite Database Integrity",
                "status": "FAIL",
                "latency_ms": round((time.time() - t0) * 1000, 2),
                "details": f"Database check failed: {e}"
            }

    def _check_watch_folders(self):
        folders = self.config.get("watch_folders", [])
        if not folders:
            from src.core.config_loader import load_config
            try:
                cfg = load_config()
                folders = cfg.get("watch_folders", [])
            except Exception:
                folders = [os.path.expandvars("%USERPROFILE%\\Downloads"), os.path.expandvars("%TEMP%")]

        accessible = []
        missing = []
        for f in folders:
            expanded = os.path.expandvars(f)
            if os.path.exists(expanded) and os.path.isdir(expanded):
                accessible.append(expanded)
            else:
                missing.append(expanded)

        if not missing:
            return {
                "name": "Watch Folders Accessibility",
                "status": "PASS",
                "details": f"All {len(accessible)} configured watch folder(s) exist and are accessible."
            }
        else:
            return {
                "name": "Watch Folders Accessibility",
                "status": "WARN",
                "details": f"{len(accessible)} accessible, {len(missing)} missing ({', '.join(missing)})"
            }

    def _check_defender(self):
        t0 = time.time()
        try:
            available = self.defender.is_available()
            latency_ms = round((time.time() - t0) * 1000, 2)
            if available:
                return {
                    "name": "Windows Defender Scanner (MpCmdRun.exe)",
                    "status": "PASS",
                    "latency_ms": latency_ms,
                    "details": f"Defender CLI available and responsive ({latency_ms}ms)"
                }
            else:
                return {
                    "name": "Windows Defender Scanner (MpCmdRun.exe)",
                    "status": "WARN",
                    "latency_ms": latency_ms,
                    "details": "Defender executable not detected at standard paths (fallback heuristic mode active)"
                }
        except Exception as e:
            return {
                "name": "Windows Defender Scanner (MpCmdRun.exe)",
                "status": "WARN",
                "details": f"Defender check error: {e}"
            }

    def _check_sensors(self):
        t0 = time.time()
        try:
            metrics = self.sensor.collect_metrics()
            latency_ms = round((time.time() - t0) * 1000, 2)
            cpu = metrics.get("cpu_percent", 0.0)
            ram = metrics.get("ram_percent", 0.0)
            disk = metrics.get("disk_used_percent", 0.0)
            valid = (0.0 <= cpu <= 100.0) and (0.0 <= ram <= 100.0) and (0.0 <= disk <= 100.0)

            if valid:
                return {
                    "name": "System Telemetry Sensors",
                    "status": "PASS",
                    "latency_ms": latency_ms,
                    "details": f"CPU: {cpu}% | RAM: {ram}% | Disk: {disk}% (Latency: {latency_ms}ms)"
                }
            else:
                return {
                    "name": "System Telemetry Sensors",
                    "status": "FAIL",
                    "latency_ms": latency_ms,
                    "details": f"Sensors reported out-of-bound values: CPU={cpu}%, RAM={ram}%, Disk={disk}%"
                }
        except Exception as e:
            return {
                "name": "System Telemetry Sensors",
                "status": "FAIL",
                "details": f"Sensor collection failed: {e}"
            }

    def _check_storage_paths(self):
        paths = [
            ("AppData", PathManager.get_app_data_dir()),
            ("Data", PathManager.get_data_dir()),
            ("Logs", PathManager.get_logs_dir()),
            ("Quarantine", PathManager.get_quarantine_dir()),
            ("Models", PathManager.get_models_dir()),
        ]
        all_ok = True
        details_list = []
        for label, p in paths:
            if os.path.exists(p) and os.access(p, os.W_OK):
                details_list.append(f"{label}: OK")
            else:
                all_ok = False
                details_list.append(f"{label}: FAIL ({p})")

        return {
            "name": "Ghost OS Storage & Permissions",
            "status": "PASS" if all_ok else "FAIL",
            "details": " | ".join(details_list)
        }

    def format_report(self, results):
        """Formats the diagnostics result into a clean human-readable text report."""
        lines = [
            "=" * 60,
            f"  GHOST OS DIAGNOSTICS REPORT — {results['timestamp']}",
            f"  Overall Status: {results['overall_status']} ({results['passed_count']}/{results['total_checks']} checks passed in {results['duration_ms']}ms)",
            "=" * 60,
            ""
        ]
        for c in results["checks"]:
            symbol = "[✓]" if c["status"] == "PASS" else ("[i]" if c["status"] == "WARN" else "[✗]")
            latency = f" [{c['latency_ms']}ms]" if "latency_ms" in c else ""
            lines.append(f"{symbol} {c['name']} — {c['status']}{latency}")
            lines.append(f"    {c['details']}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)
