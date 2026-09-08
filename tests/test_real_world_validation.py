import os
import sys
import time
import tempfile
import shutil
import unittest
import threading

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.ghost_core import GhostCore, STATE_WATCHING, STATE_PAUSED, STATE_NORMAL
from src.database.db_manager import DBManager
from src.actions.cleaner import SystemCleaner
from src.actions.quarantine_manager import QuarantineManager
from src.actions.diagnostics_job import DiagnosticsJob
from src.decision.safety_engine import SafetyEngine
from src.decision.decision_engine import DecisionEngine, ASK_USER, NOTIFY, LOG
from src.notifications.notifier import Notifier


class TestRealWorldValidation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ghost_real_test_")
        self.db_path = os.path.join(self.tmpdir, "test_telemetry.db")
        DBManager._instance = None
        self.db = DBManager(db_path=self.db_path)

        # Create temporary disposable test root
        self.disposable_dir = os.path.join(self.tmpdir, "AppData", "Local", "Temp")
        os.makedirs(self.disposable_dir, exist_ok=True)

        self.config = {
            "ghost": {"startup": False},
            "monitoring": {
                "system_interval_seconds": 1,
                "process_interval_seconds": 2,
                "db_cleanup_days": 7
            },
            "thresholds": {
                "cpu": {"critical_percent": 90.0, "consecutive_ticks": 3},
                "memory": {"critical_percent": 95.0},
                "disk": {"warning_percent": 90.0}
            },
            "notifications": {
                "enabled": True,
                "cooldown_seconds": 1,
                "aggregate_window_seconds": 2
            },
            "watch_folders": [self.disposable_dir],
            "cleanup": {
                "enabled": True,
                "require_confirmation": True,
                "stale_temp_hours": 24,
                "check_interval_seconds": 0.2
            },
            "security": {
                "behavioral_monitoring": True,
                "protected_processes": ["explorer.exe", "lsass.exe"],
                "protected_paths": ["C:\\Windows", "C:\\Program Files"]
            },
            "automation": {
                "enabled": True,
                "auto_trim_memory": False,
                "auto_lower_priority": False
            },
            "safety": {
                "dry_run": True
            }
        }

        self.safety = SafetyEngine(config=self.config)

        self.cleaner = SystemCleaner(
            self.safety,
            db_mgr=self.db,
            require_confirmation=True,
            min_age_hours=24
        )
        self.cleaner.disposable_roots = [self.disposable_dir]

    def tearDown(self):
        self.db.close()
        DBManager._instance = None
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    # =========================================================================
    # 1. Real Junk & Temp Cleanup Test
    # =========================================================================
    def test_real_junk_and_temp_cleanup_workflow(self):
        # 1. Create Stale File (>24h old, e.g. 48 hours ago)
        stale_file = os.path.join(self.disposable_dir, "stale_temp_dump.tmp")
        with open(stale_file, "wb") as f:
            f.write(b"0" * 1024 * 1024 * 2)  # 2 MB
        past_time = time.time() - (48 * 3600)
        os.utime(stale_file, (past_time, past_time))

        # 2. Create Fresh File (<24h old, e.g. 1 hour ago)
        fresh_file = os.path.join(self.disposable_dir, "fresh_active_file.tmp")
        with open(fresh_file, "wb") as f:
            f.write(b"0" * 1024 * 512)  # 512 KB
        fresh_time = time.time() - (3600)
        os.utime(fresh_file, (fresh_time, fresh_time))

        # 3. Create Locked / In-Use File (>24h old but open handle in write mode)
        locked_file = os.path.join(self.disposable_dir, "locked_session.log")
        with open(locked_file, "wb") as f:
            f.write(b"active logging session")
        os.utime(locked_file, (past_time, past_time))
        open_handle = open(locked_file, "r+b")

        try:
            # Test discover_detailed
            detailed = self.cleaner.discover_detailed(min_age_hours=24)
            self.assertGreaterEqual(len(detailed), 3)

            status_map = {item["name"]: item["status"] for item in detailed}
            size_map = {item["name"]: item["size_mb"] for item in detailed}

            # Verify classification
            self.assertEqual(status_map.get("stale_temp_dump.tmp"), "SAFE TO CLEAN")
            self.assertEqual(status_map.get("fresh_active_file.tmp"), "TOO RECENT")
            self.assertEqual(status_map.get("locked_session.log"), "IN USE")

            # Verify sizes and attributes
            self.assertGreaterEqual(size_map.get("stale_temp_dump.tmp"), 1.9)
            for item in detailed:
                self.assertIn("root_folder", item)
                self.assertIn("age_display", item)
                self.assertIn("reason", item)
                self.assertIn("category", item)

            # Test standard discover (only returns SAFE TO CLEAN)
            candidates = self.cleaner.discover(min_age_hours=24)
            cand_names = [c["name"] for c in candidates]
            self.assertIn("stale_temp_dump.tmp", cand_names)
            self.assertNotIn("fresh_active_file.tmp", cand_names)
            self.assertNotIn("locked_session.log", cand_names)

            # Test dry_run execution (files should NOT be deleted)
            self.safety.dry_run = True
            dry_res = self.cleaner.execute(candidates)
            self.assertTrue(dry_res["dry_run"])
            self.assertTrue(os.path.exists(stale_file))

            # Test live execution (stale file deleted, locked and fresh files preserved)
            self.safety.dry_run = False
            live_res = self.cleaner.execute(candidates)
            self.assertFalse(live_res["dry_run"])
            self.assertEqual(live_res["files_removed"], 1)
            self.assertFalse(os.path.exists(stale_file))
            self.assertTrue(os.path.exists(fresh_file))
            self.assertTrue(os.path.exists(locked_file))

        finally:
            open_handle.close()

    # =========================================================================
    # 2. 5-Minute Cleanup Notification Loop
    # =========================================================================
    def test_cleanup_notification_and_deduplication(self):
        core = GhostCore(self.config, db_mgr=self.db)
        core.cleaner.disposable_roots = [self.disposable_dir]

        notif_proposals = []
        core.notifier.notify_cleanup_proposal = lambda count, size_mb, on_review, on_clean_now=None, on_later=None: notif_proposals.append({
            "count": count, "size_mb": size_mb, "on_review": on_review, "on_clean_now": on_clean_now, "on_later": on_later
        })

        # Create large stale files (>5 MB total)
        for i in range(3):
            p = os.path.join(self.disposable_dir, f"big_temp_{i}.tmp")
            with open(p, "wb") as f:
                f.write(b"1" * 1024 * 1024 * 3)  # 3 MB each = 9 MB total
            past = time.time() - (48 * 3600)
            os.utime(p, (past, past))

        # Run periodic check loop once
        t = threading.Thread(target=core._periodic_cleanup_loop, daemon=True)
        t.start()
        time.sleep(0.6)
        core.stop()
        t.join(timeout=2.0)

        self.assertGreaterEqual(len(notif_proposals), 1)
        prop = notif_proposals[0]
        self.assertEqual(prop["count"], 3)
        self.assertGreaterEqual(prop["size_mb"], 8.5)
        self.assertIsNotNone(prop["on_review"])
        self.assertIsNotNone(prop["on_clean_now"])
        self.assertIsNotNone(prop["on_later"])

    # =========================================================================
    # 3. Security Notifications & Decision Engine
    # =========================================================================
    def test_security_notification_actions(self):
        core = GhostCore(self.config, db_mgr=self.db)
        quar_events = []
        core.notifier.notify_quarantined = lambda path, score: quar_events.append(path)

        # Create safe test file
        test_suspicious = os.path.join(self.tmpdir, "invoice_scan.pdf.exe")
        with open(test_suspicious, "wb") as f:
            f.write(b"MZ synthetic executable test")

        # Test user response handler: 'quarantine'
        core.safety.dry_run = False
        core._handle_user_response(101, test_suspicious, "quarantine")
        self.assertFalse(os.path.exists(test_suspicious))
        self.assertEqual(len(quar_events), 1)

        # Test user response handler: 'leave_alone'
        clean_file = os.path.join(self.tmpdir, "app_installer.exe")
        with open(clean_file, "wb") as f:
            f.write(b"MZ installer")
        core._handle_user_response(102, clean_file, "leave_alone")
        self.assertTrue(os.path.exists(clean_file))

    # =========================================================================
    # 4. Activity Log Categories and Filters
    # =========================================================================
    def test_activity_log_categories_and_filters(self):
        # Insert events across different categories
        self.db.log_guardian_event("C:\\test\\a.exe", "rule_engine", "Clean installer", "LOW", 20, classification="LOW_RISK")
        self.db.log_guardian_event("C:\\test\\b.exe", "rule_engine", "Malicious double extension", "HIGH", 80, classification="THREAT")
        self.db.log_cleanup_event(12, 3, 45.5, ["%TEMP%"], False)
        self.db.log_anomaly("system", "CPU", "cpu_sustained", 94.0, "High CPU usage")
        self.db.insert_system_metrics(
            cpu=45.0, ram=60.0, disk_pct=70.0,
            disk_read=0.0, disk_write=0.0, net_sent=0.0, net_recv=0.0
        )

        # Test ALL
        all_act = self.db.get_unified_activity(limit=50, category_filter="ALL")
        self.assertGreaterEqual(len(all_act), 3)

        # Test SECURITY
        sec_act = self.db.get_unified_activity(limit=50, category_filter="SECURITY")
        self.assertTrue(all(a["category"] == "SECURITY" for a in sec_act))

        # Test CLEANUP
        clean_act = self.db.get_unified_activity(limit=50, category_filter="CLEANUP")
        self.assertTrue(all(a["category"] == "CLEANUP" for a in clean_act))
        self.assertIn("45.5 MB", clean_act[0]["description"])

        # Test QUARANTINE
        quar_act = self.db.get_unified_activity(limit=50, category_filter="QUARANTINE")
        self.assertTrue(all(a["category"] == "QUARANTINE" for a in quar_act))

        # Test clear history
        self.db.clear_activity_history(category_filter="CLEANUP")
        clean_after = self.db.get_unified_activity(limit=50, category_filter="CLEANUP")
        self.assertEqual(len(clean_after), 0)

    # =========================================================================
    # 5. Quarantine Vault Workflow
    # =========================================================================
    def test_quarantine_vault_lifecycle(self):
        vault_dir = os.path.join(self.tmpdir, "vault")
        qm = QuarantineManager(quarantine_dir=vault_dir, db_mgr=self.db)

        # Create safe test file to quarantine
        sample_path = os.path.join(self.tmpdir, "suspicious_payload.scr")
        content = b"TEST_PAYLOAD_BINARY_CONTENT"
        with open(sample_path, "wb") as f:
            f.write(content)

        # Quarantine
        success, q_path, sha = qm.quarantine_file(event_id=201, file_path=sample_path)
        self.assertTrue(success)
        self.assertFalse(os.path.exists(sample_path))
        self.assertTrue(os.path.exists(q_path))

        # Verify items
        items = qm.get_quarantined_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["original_path"], sample_path)
        self.assertEqual(items[0]["file_hash"], sha)

        # Restore
        restored, err = qm.restore_file(q_path, sample_path)
        self.assertTrue(restored)
        self.assertTrue(os.path.exists(sample_path))
        with open(sample_path, "rb") as f:
            self.assertEqual(f.read(), content)

    # =========================================================================
    # 6. System Health / 10-Subsystem Diagnostics
    # =========================================================================
    def test_diagnostics_10_subsystem_health(self):
        core = GhostCore(self.config, db_mgr=self.db)
        diag = DiagnosticsJob(config=self.config, db_mgr=self.db, ghost_core=core)
        res = diag.run_all_checks()

        self.assertIn(res["state"], ["COMPLETED", "RUNNING"])
        checks = res["checks"]
        self.assertGreaterEqual(len(checks), 10)

        for r in checks:
            self.assertIn(r["status"], ["PASS", "WARNING", "FAILED"])
            self.assertGreaterEqual(r.get("latency_ms", 0), 0)
            self.assertTrue(len(r.get("explanation", "")) > 0)

    # =========================================================================
    # 7. Continuous Monitoring Isolation
    # =========================================================================
    def test_continuous_monitoring_isolation_during_manual_jobs(self):
        core = GhostCore(self.config, db_mgr=self.db)
        core.start()
        time.sleep(0.3)

        self.assertEqual(core.get_health_state(), STATE_WATCHING)
        self.assertTrue(core.running)

        # Run manual scan
        scan = core.create_manual_scan()
        scan_started = scan.start()
        self.assertTrue(scan_started)
        time.sleep(0.5)

        # Run diagnostics
        diag_res = core.run_diagnostics()
        self.assertIn("checks", diag_res)

        # Run cleanup
        clean_res = core.preview_cleanup()
        self.assertIn("count", clean_res)

        # Verify core remains watching and threads survive
        self.assertEqual(core.get_health_state(), STATE_WATCHING)
        self.assertTrue(core.running)
        core.stop()


if __name__ == "__main__":
    unittest.main()
