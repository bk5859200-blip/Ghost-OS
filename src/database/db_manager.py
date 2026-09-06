import sqlite3
import os
import time
import json
import threading
from datetime import datetime, timedelta

from src.core.path_manager import PathManager

class DBManager:
    """
    Manages SQLite connections and persistent event memory for Ghost OS.
    Thread-safe implementation with per-thread connection caching in WAL mode
    and write-buffering for high-frequency telemetry.
    """
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(DBManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path=None):
        target_path = db_path or PathManager.get_database_path()
        if getattr(self, "_initialized", False) and getattr(self, "db_path", None) == target_path:
            return
        self.db_path = target_path
        self._local = threading.local()
        self._sys_metrics_buffer = []
        self._proc_metrics_buffer = []
        self._buffer_lock = threading.Lock()
        self._last_flush_time = time.time()
        self._flush_interval = 5.0
        self._flush_threshold = 20
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()
        self._initialized = True

    def get_connection(self):
        """Returns a cached per-thread SQLite connection in WAL mode."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def flush(self):
        """Flushes buffered system and process metrics to SQLite in batches."""
        with self._buffer_lock:
            sys_rows = self._sys_metrics_buffer[:]
            self._sys_metrics_buffer.clear()
            proc_rows = self._proc_metrics_buffer[:]
            self._proc_metrics_buffer.clear()
            self._last_flush_time = time.time()

        if not sys_rows and not proc_rows:
            return

        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            if sys_rows:
                cursor.executemany("""
                    INSERT INTO system_metrics 
                    (timestamp, cpu_percent, ram_percent, disk_used_percent, disk_read_rate, disk_write_rate, net_sent_rate, net_recv_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, sys_rows)
            if proc_rows:
                cursor.executemany("""
                    INSERT INTO process_metrics (timestamp, pid, name, cpu_percent, memory_rss_mb, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, proc_rows)
            conn.commit()

    def close(self):
        """Flushes buffers and closes the cached thread connection."""
        self.flush()
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def init_db(self):
        """Initializes all telemetry, event, quarantine, and notification tables."""
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()

            # 1. System Metrics Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    ram_percent REAL NOT NULL,
                    disk_used_percent REAL NOT NULL,
                    disk_read_rate REAL NOT NULL,
                    disk_write_rate REAL NOT NULL,
                    net_sent_rate REAL NOT NULL,
                    net_recv_rate REAL NOT NULL
                )
            """)

            # 2. Process Telemetry Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS process_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    memory_rss_mb REAL NOT NULL,
                    status TEXT NOT NULL
                )
            """)

            # 3. Process Events (Creation / Termination / Anomalous Spawns)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS process_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,      -- 'started' | 'ended'
                    pid INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    exe_path TEXT,
                    parent_pid INTEGER,
                    parent_name TEXT,
                    cpu_percent REAL DEFAULT 0.0,
                    memory_rss_mb REAL DEFAULT 0.0,
                    anomaly_flag INTEGER DEFAULT 0
                )
            """)

            # 4. Guardian Events (Threat Sentinel and Defender detections)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS guardian_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    detector TEXT NOT NULL,        -- 'threat_sentinel' | 'defender' | 'rule_engine'
                    reason TEXT NOT NULL,
                    severity TEXT NOT NULL,        -- 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
                    risk_score INTEGER DEFAULT 0,
                    signals_json TEXT,
                    status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'quarantined' | 'deleted' | 'ignored'
                    resolved_at TEXT
                )
            """)

            # 5. Quarantine Log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    file_hash TEXT,
                    file_size INTEGER DEFAULT 0,
                    quarantined_at TEXT NOT NULL,
                    restored INTEGER NOT NULL DEFAULT 0,
                    restored_at TEXT,
                    FOREIGN KEY(event_id) REFERENCES guardian_events(id)
                )
            """)

            # 6. Cleanup Events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cleanup_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    files_removed INTEGER NOT NULL,
                    dirs_removed INTEGER NOT NULL,
                    space_recovered_mb REAL NOT NULL,
                    categories_json TEXT,
                    dry_run INTEGER NOT NULL DEFAULT 1
                )
            """)

            # 7. Notifications Log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    signal_key TEXT,
                    severity TEXT DEFAULT 'INFO',
                    suppressed_count INTEGER DEFAULT 0,
                    delivered INTEGER DEFAULT 1
                )
            """)

            # 8. Anomaly Log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,           -- 'system' | 'process' | 'filesystem'
                    entity_name TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,     -- 'cpu_burst' | 'suspicious_child' | 'baseline_deviation'
                    score REAL NOT NULL,
                    description TEXT NOT NULL,
                    details_json TEXT
                )
            """)

            # Create Indexes for efficient timestamp queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sys_time ON system_metrics(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_proc_time ON process_metrics(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON guardian_events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_proc_events_time ON process_events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_time ON anomalies(timestamp);")

            conn.commit()

    def purge_old_records(self, retention_days=7):
        """Deletes high-frequency telemetry rows older than retention_days."""
        self.flush()
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat()
            cursor.execute("DELETE FROM system_metrics WHERE timestamp < ?", (cutoff,))
            cursor.execute("DELETE FROM process_metrics WHERE timestamp < ?", (cutoff,))
            conn.commit()

    def log_process_event(self, event_type, pid, name, exe_path=None, parent_pid=None,
                          parent_name=None, cpu_percent=0.0, memory_rss_mb=0.0, anomaly_flag=0):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO process_events 
                (timestamp, event_type, pid, name, exe_path, parent_pid, parent_name, cpu_percent, memory_rss_mb, anomaly_flag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, event_type, pid, name, exe_path, parent_pid, parent_name, cpu_percent, memory_rss_mb, anomaly_flag))
            conn.commit()
            return cursor.lastrowid

    def log_guardian_event(self, file_path, detector, reason, severity, risk_score=0, signals=None):
        """Records a security detection. Returns the new event ID."""
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            signals_json = json.dumps(signals) if signals is not None else None
            cursor.execute("""
                INSERT INTO guardian_events 
                (timestamp, file_path, detector, reason, severity, risk_score, signals_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            """, (timestamp, file_path, detector, reason, severity, risk_score, signals_json))
            conn.commit()
            return cursor.lastrowid

    def resolve_guardian_event(self, event_id, status):
        """Marks an event as quarantined / deleted / ignored."""
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE guardian_events SET status = ?, resolved_at = ? WHERE id = ?
            """, (status, datetime.now().isoformat(), event_id))
            conn.commit()

    def log_quarantine(self, event_id, original_path, quarantine_path, file_hash=None, file_size=0):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantine_log (event_id, original_path, quarantine_path, file_hash, file_size, quarantined_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (event_id, original_path, quarantine_path, file_hash, file_size, datetime.now().isoformat()))
            conn.commit()
            return cursor.lastrowid

    def mark_quarantine_restored(self, quarantine_path):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE quarantine_log SET restored = 1, restored_at = ? WHERE quarantine_path = ?
            """, (datetime.now().isoformat(), quarantine_path))
            conn.commit()

    def get_quarantine_by_path(self, quarantine_path):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_log WHERE quarantine_path = ? ORDER BY id DESC LIMIT 1", (quarantine_path,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def log_cleanup_event(self, files_removed, dirs_removed, space_recovered_mb, categories=None, dry_run=True):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            categories_json = json.dumps(categories) if categories is not None else None
            cursor.execute("""
                INSERT INTO cleanup_events (timestamp, files_removed, dirs_removed, space_recovered_mb, categories_json, dry_run)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp, files_removed, dirs_removed, space_recovered_mb, categories_json, 1 if dry_run else 0))
            conn.commit()
            return cursor.lastrowid

    def log_notification(self, title, message, signal_key=None, severity="INFO", suppressed_count=0, delivered=True):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO notifications (timestamp, title, message, signal_key, severity, suppressed_count, delivered)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, title, message, signal_key, severity, suppressed_count, 1 if delivered else 0))
            conn.commit()
            return cursor.lastrowid

    def log_anomaly(self, source, entity_name, anomaly_type, score, description, details=None):
        with self._lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            details_json = json.dumps(details) if details is not None else None
            cursor.execute("""
                INSERT INTO anomalies (timestamp, source, entity_name, anomaly_type, score, description, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, source, entity_name, anomaly_type, score, description, details_json))
            conn.commit()
            return cursor.lastrowid

    def get_recent_events(self, limit=50):
        self.flush()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM guardian_events ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def insert_system_metrics(self, cpu, ram, disk_pct, disk_read, disk_write, net_sent, net_recv):
        timestamp = datetime.now().isoformat()
        row = (timestamp, cpu, ram, disk_pct, disk_read, disk_write, net_sent, net_recv)
        should_flush = False
        with self._buffer_lock:
            self._sys_metrics_buffer.append(row)
            if len(self._sys_metrics_buffer) >= self._flush_threshold or (time.time() - self._last_flush_time >= self._flush_interval):
                should_flush = True
        if should_flush:
            self.flush()

    def insert_process_metrics(self, processes):
        if not processes:
            return
        timestamp = datetime.now().isoformat()
        rows = [(timestamp, p['pid'], p['name'], p['cpu_percent'], p['memory_rss_mb'], p['status']) for p in processes]
        should_flush = False
        with self._buffer_lock:
            self._proc_metrics_buffer.extend(rows)
            if len(self._proc_metrics_buffer) >= self._flush_threshold or (time.time() - self._last_flush_time >= self._flush_interval):
                should_flush = True
        if should_flush:
            self.flush()

    def get_latest_system_metrics(self, limit=100):
        self.flush()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM system_metrics ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in reversed(rows)]

    def get_away_summary(self, window_hours=4):
        """
        Generates structured digest for "What happened while I was away?"
        Queries real stored events over the given timeframe.
        """
        self.flush()
        conn = self.get_connection()
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=window_hours)).isoformat()

        # Cleanups
        cursor.execute("""
            SELECT COUNT(*), COALESCE(SUM(space_recovered_mb), 0.0) 
            FROM cleanup_events WHERE timestamp >= ?
        """, (cutoff,))
        cleanup_row = cursor.fetchone()
        cleanups_count = cleanup_row[0] if cleanup_row else 0
        space_recovered_mb = cleanup_row[1] if cleanup_row else 0.0

        # Anomalies
        cursor.execute("SELECT COUNT(*) FROM anomalies WHERE timestamp >= ?", (cutoff,))
        anomalies_count = cursor.fetchone()[0]

        # Suspicious detections
        cursor.execute("SELECT COUNT(*) FROM guardian_events WHERE timestamp >= ? AND severity IN ('MEDIUM', 'HIGH', 'CRITICAL')", (cutoff,))
        suspicious_count = cursor.fetchone()[0]

        # Quarantined files
        cursor.execute("SELECT COUNT(*) FROM quarantine_log WHERE quarantined_at >= ?", (cutoff,))
        quarantined_count = cursor.fetchone()[0]

        # Process starts
        cursor.execute("SELECT COUNT(*) FROM process_events WHERE timestamp >= ? AND event_type = 'started'", (cutoff,))
        proc_starts_count = cursor.fetchone()[0]

        # Recent anomaly highlights
        cursor.execute("SELECT description, score, timestamp FROM anomalies WHERE timestamp >= ? ORDER BY id DESC LIMIT 5", (cutoff,))
        recent_anomalies = [dict(row) for row in cursor.fetchall()]

        status_assessment = "Everything is stable."
        if suspicious_count > 0 or anomalies_count > 5:
            status_assessment = "Attention recommended — unusual activity was detected."

        return {
            "window_hours": window_hours,
            "cleanups_count": cleanups_count,
            "space_recovered_mb": round(space_recovered_mb, 1),
            "anomalies_count": anomalies_count,
            "suspicious_count": suspicious_count,
            "quarantined_count": quarantined_count,
            "process_starts_count": proc_starts_count,
            "recent_anomalies": recent_anomalies,
            "status_assessment": status_assessment
        }
