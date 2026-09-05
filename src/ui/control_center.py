import os
import sys
import time
import json
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from src.core.path_manager import PathManager
from src.core.config_loader import load_config, ConfigError
from src.actions.scan_job import ManualScanJob
from src.actions.diagnostics_job import DiagnosticsJob

# Theme Color Palette
BG_DARK = "#181825"
BG_CARD = "#1e1e2e"
BG_INPUT = "#313244"
FG_MAIN = "#cdd6f4"
FG_MUTED = "#a6adc8"
ACCENT_PURPLE = "#8c78ff"
ACCENT_BLUE = "#89b4fa"
ACCENT_GREEN = "#a6e3a1"
ACCENT_YELLOW = "#f9e2af"
ACCENT_RED = "#f38ba8"


class ControlCenterApp:
    """
    Tkinter Native Control Center for Ghost OS.
    Features: Overview, Quick Scan, Quarantine Manager, Activity History, Settings, and Diagnostics.
    """

    def __init__(self, ghost_core, initial_tab="overview"):
        self.core = ghost_core
        self.root = tk.Tk()
        self.root.title("Ghost OS — Control Center 👻")
        self.root.geometry("860x600")
        self.root.minsize(760, 500)
        self.root.configure(bg=BG_DARK)

        self._active_scan_job = None
        self._setup_styles()
        self._build_ui()
        self._select_tab(initial_tab)
        self._schedule_telemetry_update()

    def _setup_styles(self):
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")

        # Global Frame and Label styling
        self.style.configure(".", background=BG_DARK, foreground=FG_MAIN, font=("Segoe UI", 9))
        self.style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=BG_CARD, foreground=FG_MUTED,
                             padding=[12, 6], font=("Segoe UI", 9, "bold"))
        self.style.map("TNotebook.Tab",
                       background=[("selected", ACCENT_PURPLE)],
                       foreground=[("selected", "#ffffff")])

        self.style.configure("Card.TFrame", background=BG_CARD, relief="flat")
        self.style.configure("Header.TLabel", background=BG_CARD, foreground=FG_MAIN, font=("Segoe UI", 12, "bold"))
        self.style.configure("Subheader.TLabel", background=BG_CARD, foreground=FG_MUTED, font=("Segoe UI", 9))
        self.style.configure("Value.TLabel", background=BG_CARD, foreground=ACCENT_BLUE, font=("Segoe UI", 16, "bold"))

        # Buttons
        self.style.configure("Accent.TButton", background=ACCENT_PURPLE, foreground="#ffffff",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=6)
        self.style.map("Accent.TButton", background=[("active", "#7a66f0"), ("disabled", "#45475a")])

        self.style.configure("Secondary.TButton", background=BG_INPUT, foreground=FG_MAIN,
                             font=("Segoe UI", 9), borderwidth=0, padding=6)
        self.style.map("Secondary.TButton", background=[("active", "#45475a"), ("disabled", "#313244")])

        self.style.configure("Danger.TButton", background=ACCENT_RED, foreground="#11111b",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=6)
        self.style.map("Danger.TButton", background=[("active", "#e78284"), ("disabled", "#45475a")])

        # Progressbar & Treeview
        self.style.configure("Accent.Horizontal.TProgressbar", background=ACCENT_PURPLE, troughcolor=BG_INPUT)
        self.style.configure("Treeview", background=BG_CARD, foreground=FG_MAIN,
                             fieldbackground=BG_CARD, borderwidth=0, rowheight=24)
        self.style.configure("Treeview.Heading", background=BG_INPUT, foreground=FG_MAIN,
                             font=("Segoe UI", 9, "bold"), relief="flat")
        self.style.map("Treeview", background=[("selected", ACCENT_PURPLE)], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        # Header banner
        header_frame = tk.Frame(self.root, bg=BG_CARD, height=50)
        header_frame.pack(fill="x", side="top", padx=10, pady=(10, 5))

        title_lbl = tk.Label(header_frame, text="👻 Ghost OS Background Guardian",
                             bg=BG_CARD, fg=FG_MAIN, font=("Segoe UI", 14, "bold"))
        title_lbl.pack(side="left", padx=15, pady=10)

        self.state_badge = tk.Label(header_frame, text="WATCHING",
                                    bg=ACCENT_GREEN, fg="#11111b", font=("Segoe UI", 9, "bold"), padx=8, pady=3)
        self.state_badge.pack(side="right", padx=15, pady=10)

        # Tab Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_overview = ttk.Frame(self.notebook)
        self.tab_scan = ttk.Frame(self.notebook)
        self.tab_quarantine = ttk.Frame(self.notebook)
        self.tab_activity = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        self.tab_diagnostics = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_overview, text="  Overview  ")
        self.notebook.add(self.tab_scan, text="  Quick Scan  ")
        self.notebook.add(self.tab_quarantine, text="  Quarantine  ")
        self.notebook.add(self.tab_activity, text="  Activity History  ")
        self.notebook.add(self.tab_settings, text="  Policy Settings  ")
        self.notebook.add(self.tab_diagnostics, text="  Diagnostics  ")

        self._build_overview_tab()
        self._build_scan_tab()
        self._build_quarantine_tab()
        self._build_activity_tab()
        self._build_settings_tab()
        self._build_diagnostics_tab()

    # ------------------------------------------------------------- 1. OVERVIEW TAB
    def _build_overview_tab(self):
        f = self.tab_overview

        # Telemetry metrics row
        metrics_frame = tk.Frame(f, bg=BG_DARK)
        metrics_frame.pack(fill="x", padx=10, pady=10)
        metrics_frame.columnconfigure((0, 1, 2, 3), weight=1)

        # CPU Card
        c1 = ttk.Frame(metrics_frame, style="Card.TFrame", padding=10)
        c1.grid(row=0, column=0, padx=5, sticky="nsew")
        ttk.Label(c1, text="CPU Usage", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_cpu = ttk.Label(c1, text="0.0%", style="Value.TLabel")
        self.lbl_cpu.pack(anchor="w", pady=4)

        # RAM Card
        c2 = ttk.Frame(metrics_frame, style="Card.TFrame", padding=10)
        c2.grid(row=0, column=1, padx=5, sticky="nsew")
        ttk.Label(c2, text="RAM Usage", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_ram = ttk.Label(c2, text="0.0%", style="Value.TLabel")
        self.lbl_ram.pack(anchor="w", pady=4)

        # Disk Card
        c3 = ttk.Frame(metrics_frame, style="Card.TFrame", padding=10)
        c3.grid(row=0, column=2, padx=5, sticky="nsew")
        ttk.Label(c3, text="Disk Usage", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_disk = ttk.Label(c3, text="0.0%", style="Value.TLabel")
        self.lbl_disk.pack(anchor="w", pady=4)

        # Protection State Card
        c4 = ttk.Frame(metrics_frame, style="Card.TFrame", padding=10)
        c4.grid(row=0, column=3, padx=5, sticky="nsew")
        ttk.Label(c4, text="Guardian Mode", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_mode = ttk.Label(c4, text="ACTIVE", style="Value.TLabel")
        self.lbl_mode.pack(anchor="w", pady=4)

        # Away Summary Digest Card
        summary_frame = ttk.Frame(f, style="Card.TFrame", padding=15)
        summary_frame.pack(fill="both", expand=True, padx=15, pady=5)

        ttk.Label(summary_frame, text="Activity Digest — Past 24 Hours", style="Header.TLabel").pack(anchor="w")
        self.txt_digest = tk.Text(summary_frame, bg=BG_INPUT, fg=FG_MAIN, height=8,
                                  font=("Consolas", 9), relief="flat", padx=10, pady=10)
        self.txt_digest.pack(fill="both", expand=True, pady=10)

        # Quick Actions Row
        action_bar = tk.Frame(f, bg=BG_DARK)
        action_bar.pack(fill="x", padx=15, pady=10)

        ttk.Button(action_bar, text="▶ Run Quick Scan", style="Accent.TButton",
                   command=lambda: self._select_tab("scan")).pack(side="left", padx=5)
        ttk.Button(action_bar, text="🧹 Propose System Cleanup", style="Secondary.TButton",
                   command=self._trigger_cleanup).pack(side="left", padx=5)
        self.btn_pause_toggle = ttk.Button(action_bar, text="⏸ Pause Guardian", style="Secondary.TButton",
                                           command=self._toggle_pause)
        self.btn_pause_toggle.pack(side="left", padx=5)

    # ------------------------------------------------------------- 2. QUICK SCAN TAB
    def _build_scan_tab(self):
        f = self.tab_scan

        ctrl_frame = ttk.Frame(f, style="Card.TFrame", padding=15)
        ctrl_frame.pack(fill="x", padx=15, pady=10)

        ttk.Label(ctrl_frame, text="On-Demand Security Scanner", style="Header.TLabel").pack(anchor="w")
        ttk.Label(ctrl_frame, text="Scans all configured watch folders (Downloads, Desktop, Temp) for disguised executables and threats.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 10))

        btn_row = tk.Frame(ctrl_frame, bg=BG_CARD)
        btn_row.pack(fill="x", pady=5)

        self.btn_start_scan = ttk.Button(btn_row, text="▶ Start Full Scan", style="Accent.TButton",
                                         command=self._start_scan_job)
        self.btn_start_scan.pack(side="left", padx=(0, 10))

        self.btn_cancel_scan = ttk.Button(btn_row, text="⏹ Cancel Scan", style="Danger.TButton",
                                          command=self._cancel_scan_job, state="disabled")
        self.btn_cancel_scan.pack(side="left")

        self.scan_progress = ttk.Progressbar(ctrl_frame, style="Accent.Horizontal.TProgressbar", mode="determinate")
        self.scan_progress.pack(fill="x", pady=10)

        self.lbl_scan_status = ttk.Label(ctrl_frame, text="Ready to scan.", style="Subheader.TLabel")
        self.lbl_scan_status.pack(anchor="w")

        # Results table
        results_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        results_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        ttk.Label(results_frame, text="Flagged Items & Threat Detections", style="Header.TLabel").pack(anchor="w", pady=(0, 5))

        columns = ("score", "severity", "category", "path")
        self.tree_scan = ttk.Treeview(results_frame, columns=columns, show="headings", selectmode="browse")
        self.tree_scan.heading("score", text="Risk Score")
        self.tree_scan.heading("severity", text="Severity")
        self.tree_scan.heading("category", text="Category")
        self.tree_scan.heading("path", text="File Path")

        self.tree_scan.column("score", width=80, anchor="center")
        self.tree_scan.column("severity", width=90, anchor="center")
        self.tree_scan.column("category", width=120, anchor="center")
        self.tree_scan.column("path", width=450, anchor="w")

        scroll_scan = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree_scan.yview)
        self.tree_scan.configure(yscrollcommand=scroll_scan.set)

        self.tree_scan.pack(side="left", fill="both", expand=True)
        scroll_scan.pack(side="right", fill="y")

        # Scan results action buttons
        action_row = tk.Frame(f, bg=BG_DARK)
        action_row.pack(fill="x", padx=15, pady=(0, 10))

        ttk.Button(action_row, text="🛡 Quarantine Selected", style="Accent.TButton",
                   command=self._quarantine_scan_selection).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="🗑 Delete Selected", style="Danger.TButton",
                   command=self._delete_scan_selection).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="📁 Open Location", style="Secondary.TButton",
                   command=self._open_scan_file_location).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="✕ Dismiss", style="Secondary.TButton",
                   command=self._dismiss_scan_selection).pack(side="left")

    # ------------------------------------------------------------- 3. QUARANTINE TAB
    def _build_quarantine_tab(self):
        f = self.tab_quarantine

        header_frame = ttk.Frame(f, style="Card.TFrame", padding=15)
        header_frame.pack(fill="x", padx=15, pady=10)

        ttk.Label(header_frame, text="Quarantine Vault", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="Safely isolated suspicious files. Restoring returns the file to its original location.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 10))

        btn_row = tk.Frame(header_frame, bg=BG_CARD)
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="↺ Restore Selected File", style="Accent.TButton",
                   command=self._restore_quarantine_item).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="🗑 Permanently Delete", style="Danger.TButton",
                   command=self._delete_quarantine_item).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="📁 Open Folder", style="Secondary.TButton",
                   command=self._open_quarantine_folder).pack(side="left", padx=5)
        ttk.Button(btn_row, text="🔄 Refresh", style="Secondary.TButton",
                   command=self._load_quarantine_data).pack(side="left", padx=5)

        # Quarantine list
        table_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        table_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        cols = ("id", "date", "status", "hash", "orig_path", "q_path")
        self.tree_quarantine = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_quarantine.heading("id", text="ID")
        self.tree_quarantine.heading("date", text="Date/Time")
        self.tree_quarantine.heading("status", text="Status")
        self.tree_quarantine.heading("hash", text="SHA-256")
        self.tree_quarantine.heading("orig_path", text="Original Path")
        self.tree_quarantine.heading("q_path", text="Quarantine Location")

        self.tree_quarantine.column("id", width=40, anchor="center")
        self.tree_quarantine.column("date", width=140, anchor="center")
        self.tree_quarantine.column("status", width=90, anchor="center")
        self.tree_quarantine.column("hash", width=140, anchor="center")
        self.tree_quarantine.column("orig_path", width=220, anchor="w")
        self.tree_quarantine.column("q_path", width=150, anchor="w")

        scroll_q = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_quarantine.yview)
        self.tree_quarantine.configure(yscrollcommand=scroll_q.set)

        self.tree_quarantine.pack(side="left", fill="both", expand=True)
        scroll_q.pack(side="right", fill="y")


    # ------------------------------------------------------------- 4. ACTIVITY HISTORY TAB
    def _build_activity_tab(self):
        f = self.tab_activity

        top_frame = ttk.Frame(f, style="Card.TFrame", padding=15)
        top_frame.pack(fill="x", padx=15, pady=10)

        ttk.Label(top_frame, text="Security & Event History", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top_frame, text="Persistent audit trail of guardian detections, anomalies, and maintenance actions.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 5))

        ttk.Button(top_frame, text="🔄 Refresh Log", style="Secondary.TButton",
                   command=self._load_activity_data).pack(anchor="e")

        # Events table
        table_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        table_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        cols = ("time", "detector", "severity", "target", "reason")
        self.tree_activity = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_activity.heading("time", text="Timestamp")
        self.tree_activity.heading("detector", text="Source")
        self.tree_activity.heading("severity", text="Severity")
        self.tree_activity.heading("target", text="Target File / Process")
        self.tree_activity.heading("reason", text="Reason / Details")

        self.tree_activity.column("time", width=140, anchor="center")
        self.tree_activity.column("detector", width=110, anchor="center")
        self.tree_activity.column("severity", width=80, anchor="center")
        self.tree_activity.column("target", width=220, anchor="w")
        self.tree_activity.column("reason", width=250, anchor="w")

        scroll_act = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_activity.yview)
        self.tree_activity.configure(yscrollcommand=scroll_act.set)

        self.tree_activity.pack(side="left", fill="both", expand=True)
        scroll_act.pack(side="right", fill="y")

    # ------------------------------------------------------------- 5. SETTINGS TAB
    def _build_settings_tab(self):
        f = self.tab_settings

        top_frame = ttk.Frame(f, style="Card.TFrame", padding=15)
        top_frame.pack(fill="x", padx=15, pady=10)

        ttk.Label(top_frame, text="Guardian Policy Editor (policy.yaml)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top_frame, text="Configurations are strictly validated against the policy schema before applying.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 5))

        btn_row = tk.Frame(top_frame, bg=BG_CARD)
        btn_row.pack(fill="x", pady=5)

        ttk.Button(btn_row, text="💾 Validate & Save Policy", style="Accent.TButton",
                   command=self._save_policy).pack(side="left", padx=(0, 10))
        ttk.Button(btn_row, text="↺ Reload From Disk", style="Secondary.TButton",
                   command=self._load_policy_file).pack(side="left", padx=5)

        self.lbl_policy_status = ttk.Label(top_frame, text="", style="Subheader.TLabel")
        self.lbl_policy_status.pack(anchor="w", pady=(5, 0))

        # Editor frame
        editor_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        editor_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        self.txt_policy = scrolledtext.ScrolledText(
            editor_frame, bg=BG_INPUT, fg=FG_MAIN, insertbackground=FG_MAIN,
            font=("Consolas", 10), relief="flat", padx=10, pady=10
        )
        self.txt_policy.pack(fill="both", expand=True)
        self._load_policy_file()

    # ------------------------------------------------------------- 6. DIAGNOSTICS TAB
    def _build_diagnostics_tab(self):
        f = self.tab_diagnostics

        top_frame = ttk.Frame(f, style="Card.TFrame", padding=15)
        top_frame.pack(fill="x", padx=15, pady=10)

        ttk.Label(top_frame, text="Subsystem Health & Diagnostics", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top_frame, text="Runs end-to-end verification across Defender CLI, Database, Sensors, and Watch Folders.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 5))

        self.btn_run_diag = ttk.Button(top_frame, text="⚡ Run Full Diagnostics", style="Accent.TButton",
                                       command=self._trigger_diagnostics)
        self.btn_run_diag.pack(anchor="w", pady=5)

        # Output text area
        diag_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        diag_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        self.txt_diagnostics = scrolledtext.ScrolledText(
            diag_frame, bg=BG_INPUT, fg=FG_MAIN, font=("Consolas", 10),
            relief="flat", padx=10, pady=10
        )
        self.txt_diagnostics.pack(fill="both", expand=True)
        self.txt_diagnostics.insert("1.0", "Click 'Run Full Diagnostics' to evaluate all subsystems.\n")

    # ------------------------------------------------------------- LOGIC & ACTIONS
    def _select_tab(self, tab_name):
        mapping = {
            "overview": self.tab_overview,
            "scan": self.tab_scan,
            "quarantine": self.tab_quarantine,
            "activity": self.tab_activity,
            "settings": self.tab_settings,
            "diagnostics": self.tab_diagnostics
        }
        target = mapping.get(tab_name.lower(), self.tab_overview)
        self.notebook.select(target)
        if tab_name.lower() == "quarantine":
            self._load_quarantine_data()
        elif tab_name.lower() == "activity":
            self._load_activity_data()

    def _schedule_telemetry_update(self):
        self._update_overview_telemetry()
        self.root.after(2000, self._schedule_telemetry_update)

    def _update_overview_telemetry(self):
        try:
            state = self.core.get_health_state()
            self.state_badge.config(text=state)
            if state in ("PROTECTING", "ATTENTION"):
                self.state_badge.config(bg=ACCENT_YELLOW, fg="#11111b")
            elif state == "PAUSED":
                self.state_badge.config(bg=ACCENT_RED, fg="#11111b")
            else:
                self.state_badge.config(bg=ACCENT_GREEN, fg="#11111b")

            if hasattr(self.core, "sensor"):
                metrics = self.core.sensor.collect_metrics()
                self.lbl_cpu.config(text=f"{metrics.get('cpu_percent', 0.0):.1f}%")
                self.lbl_ram.config(text=f"{metrics.get('ram_percent', 0.0):.1f}%")
                self.lbl_disk.config(text=f"{metrics.get('disk_used_percent', 0.0):.1f}%")

            is_paused = self.core._pause_event.is_set()
            self.lbl_mode.config(text="PAUSED" if is_paused else "ACTIVE")
            self.btn_pause_toggle.config(text="▶ Resume Guardian" if is_paused else "⏸ Pause Guardian")

            # Update digest summary
            summary = self.core.get_away_summary(window_hours=24)
            digest_text = (
                f"Status:             {summary['status_assessment']}\n"
                f"Cleanups Completed: {summary['cleanups_count']} ({summary['space_recovered_mb']} MB recovered)\n"
                f"Suspicious Events:  {summary['suspicious_count']}\n"
                f"Quarantined Files:  {summary['quarantined_count']}\n"
                f"Anomalies Flagged:  {summary['anomalies_count']}\n"
            )
            self.txt_digest.delete("1.0", "end")
            self.txt_digest.insert("1.0", digest_text)
        except Exception:
            pass

    def _toggle_pause(self):
        if self.core._pause_event.is_set():
            self.core.resume()
        else:
            self.core.pause()
        self._update_overview_telemetry()

    def _trigger_cleanup(self):
        self.core.propose_cleanup()
        messagebox.showinfo("Ghost OS Cleanup", "System cleanup operation initiated in background.")

    # Scan logic
    def _start_scan_job(self):
        if self._active_scan_job and self._active_scan_job.is_running:
            messagebox.showinfo("Scan In Progress", "A system scan is already running.")
            return

        self.for_each_clear_tree(self.tree_scan)
        self.scan_progress["value"] = 0
        self.btn_start_scan.config(state="disabled")
        self.btn_cancel_scan.config(state="normal")
        self.lbl_scan_status.config(text="Initializing scan...")

        def on_prog(cur, total, path):
            pct = (cur / total * 100.0) if total > 0 else 0
            self.root.after(0, lambda: self._update_scan_progress(pct, cur, total, path))

        def on_done(res):
            self.root.after(0, lambda: self._on_scan_finished(res))

        self._active_scan_job = self.core.create_manual_scan(on_progress=on_prog, on_complete=on_done)
        self._active_scan_job.start()

    def _update_scan_progress(self, pct, cur, total, path):
        self.scan_progress["value"] = pct
        short_path = os.path.basename(path)
        self.lbl_scan_status.config(text=f"Scanning ({cur}/{total}): {short_path}")

    def _on_scan_finished(self, res):
        self.scan_progress["value"] = 100
        self.btn_start_scan.config(state="normal")
        self.btn_cancel_scan.config(state="disabled")

        if res.get("error"):
            self.lbl_scan_status.config(text=f"Scan error: {res['error']}")
            return

        flagged = res.get("flagged_items", [])
        status_msg = f"Scan complete. {res.get('scanned_count', 0)} files scanned in {res.get('duration_seconds', 0)}s. {len(flagged)} threats found."
        self.lbl_scan_status.config(text=status_msg)

        for item in flagged:
            self.tree_scan.insert("", "end", values=(
                item.get("risk_score"),
                item.get("classification"),
                item.get("category"),
                item.get("file_path")
            ))

    def _cancel_scan_job(self):
        if self._active_scan_job:
            self._active_scan_job.cancel()
            self.lbl_scan_status.config(text="Cancelling scan...")

    # Quarantine logic
    def _load_quarantine_data(self):
        self.for_each_clear_tree(self.tree_quarantine)
        try:
            self.core.db_mgr.flush()
            conn = self.core.db_mgr.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT q.id, q.quarantined_at, q.restored, q.file_hash, q.original_path, q.quarantine_path
                FROM quarantine_log q
                ORDER BY q.id DESC LIMIT 100
            """)
            rows = cursor.fetchall()
            for r in rows:
                status_str = "Restored" if r["restored"] else "Quarantined"
                hash_short = r["file_hash"][:16] + "..." if r["file_hash"] else "N/A"
                self.tree_quarantine.insert("", "end", values=(
                    r["id"], r["quarantined_at"], status_str, hash_short, r["original_path"], r["quarantine_path"]
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load quarantine data: {e}")

    def _restore_quarantine_item(self):
        selected = self.tree_quarantine.selection()
        if not selected:
            messagebox.showwarning("Restore", "Please select a file from the quarantine table to restore.")
            return

        item_values = self.tree_quarantine.item(selected[0])["values"]
        status = item_values[2]
        orig_path = item_values[4]
        q_path = item_values[5]

        if status == "Restored":
            messagebox.showinfo("Already Restored", "This item has already been restored.")
            return

        confirm = messagebox.askyesno("Confirm Restore", f"Restore file back to original location?\n\n{orig_path}")
        if confirm:
            success = self.core.quarantine.restore_file(q_path, orig_path)
            if success:
                messagebox.showinfo("Success", f"File restored successfully to:\n{orig_path}")
                self._load_quarantine_data()
            else:
                messagebox.showerror("Failed", f"Failed to restore file from:\n{q_path}")

    def _open_quarantine_folder(self):
        q_dir = self.core.quarantine.quarantine_dir
        if os.name == 'nt':
            os.startfile(q_dir)
        else:
            from src.core.proc_utils import popen_hidden
            popen_hidden(['xdg-open', q_dir])

    # Activity history logic
    def _load_activity_data(self):
        self.for_each_clear_tree(self.tree_activity)
        try:
            events = self.core.db_mgr.get_recent_events(limit=50)
            for ev in events:
                self.tree_activity.insert("", "end", values=(
                    ev.get("timestamp"),
                    ev.get("detector"),
                    ev.get("severity"),
                    ev.get("file_path"),
                    ev.get("reason")
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load activity events: {e}")

    # Settings logic
    def _load_policy_file(self):
        try:
            config_path = PathManager.ensure_user_config()
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.txt_policy.delete("1.0", "end")
            self.txt_policy.insert("1.0", content)
            self.lbl_policy_status.config(text=f"Loaded: {config_path}", foreground=FG_MUTED)
        except Exception as e:
            self.lbl_policy_status.config(text=f"Error loading policy: {e}", foreground=ACCENT_RED)

    def _save_policy(self):
        content = self.txt_policy.get("1.0", "end-1c")
        config_path = PathManager.ensure_user_config()
        temp_path = config_path + ".tmp"

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Validate structural and numeric rules
            load_config(temp_path)

            # Valid -> Overwrite actual policy file
            os.replace(temp_path, config_path)
            self.lbl_policy_status.config(text="✓ Policy validated and saved successfully.", foreground=ACCENT_GREEN)
            messagebox.showinfo("Success", "Policy configuration validated and saved successfully.")
        except ConfigError as ce:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            self.lbl_policy_status.config(text=f"✗ Configuration Error: {ce}", foreground=ACCENT_RED)
            messagebox.showerror("Invalid Configuration", f"Policy validation failed:\n\n{ce}")
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            self.lbl_policy_status.config(text=f"✗ Error: {e}", foreground=ACCENT_RED)
            messagebox.showerror("Save Error", f"Failed to save policy:\n\n{e}")

    # Diagnostics logic
    def _trigger_diagnostics(self):
        if getattr(self, "_diag_running", False):
            messagebox.showinfo("Diagnostics In Progress", "Diagnostics checklist is already running.")
            return

        self._diag_running = True
        self.btn_run_diag.config(state="disabled")
        self.txt_diagnostics.delete("1.0", "end")
        self.txt_diagnostics.insert("1.0", "Running diagnostics checklist...\n")

        def worker():
            try:
                results = self.core.run_diagnostics()
                job = DiagnosticsJob(self.core.config, self.core.db_mgr, self.core)
                report = job.format_report(results)
                self.root.after(0, lambda: self._on_diagnostics_done(report))
            except Exception as e:
                err_msg = f"Diagnostics error: {e}"
                self.root.after(0, lambda: self._on_diagnostics_done(err_msg))

        threading.Thread(target=worker, name="diag_runner", daemon=True).start()

    def _on_diagnostics_done(self, report):
        self._diag_running = False
        self.btn_run_diag.config(state="normal")
        self.txt_diagnostics.delete("1.0", "end")
        self.txt_diagnostics.insert("1.0", report)

    def _quarantine_scan_selection(self):
        selected = self.tree_scan.selection()
        if not selected:
            messagebox.showwarning("Quarantine", "Please select a flagged file from the scan table to quarantine.")
            return

        item = self.tree_scan.item(selected[0])["values"]
        file_path = str(item[3])
        if not os.path.exists(file_path):
            messagebox.showerror("Error", f"File no longer exists:\n{file_path}")
            return

        confirm = messagebox.askyesno("Confirm Quarantine", f"Safely isolate this file into the Quarantine vault?\n\n{file_path}")
        if not confirm:
            return

        allowed, reason = self.core.safety.gate_action("quarantine", file_path)
        if not allowed:
            if reason == "dry_run":
                messagebox.showinfo("Dry Run Mode", f"Dry Run mode is active in policy.yaml.\n\nProposed quarantine of:\n{file_path}\nwas safely simulated without moving the file.")
            else:
                messagebox.showerror("Blocked by Safety Engine", f"Quarantine was blocked: {reason}")
            return

        event_id = self.core.db_mgr.log_guardian_event(
            file_path=file_path,
            detector="manual_scan",
            reason=f"Risk Score: {item[0]} [{item[1]}]",
            severity=str(item[1]),
            risk_score=float(item[0])
        )
        success, dest, _ = self.core.quarantine.quarantine_file(event_id, file_path)
        if success:
            messagebox.showinfo("Quarantined", f"File was safely moved to quarantine:\n{dest}")
            self.tree_scan.delete(selected[0])
            self._load_quarantine_data()
        else:
            messagebox.showerror("Error", f"Failed to quarantine file:\n{file_path}")

    def _delete_scan_selection(self):
        selected = self.tree_scan.selection()
        if not selected:
            messagebox.showwarning("Delete", "Please select a flagged file from the scan table to delete.")
            return

        item = self.tree_scan.item(selected[0])["values"]
        file_path = str(item[3])
        if not os.path.exists(file_path):
            messagebox.showerror("Error", f"File no longer exists:\n{file_path}")
            return

        confirm = messagebox.askyesno("Confirm Permanent Deletion", f"Permanently delete this file?\n\n{file_path}\n\nWARNING: This cannot be undone!")
        if not confirm:
            return

        allowed, reason = self.core.safety.gate_action("delete", file_path)
        if not allowed:
            if reason == "dry_run":
                messagebox.showinfo("Dry Run Mode", f"Dry Run mode is active in policy.yaml.\n\nProposed deletion of:\n{file_path}\nwas safely simulated without removing the file.")
            else:
                messagebox.showerror("Blocked by Safety Engine", f"Deletion was blocked: {reason}")
            return

        event_id = self.core.db_mgr.log_guardian_event(
            file_path=file_path,
            detector="manual_scan",
            reason="User confirmed deletion",
            severity=str(item[1]),
            risk_score=float(item[0])
        )
        if self.core.quarantine.delete_file(event_id, file_path):
            messagebox.showinfo("Deleted", f"File was permanently deleted:\n{file_path}")
            self.tree_scan.delete(selected[0])
        else:
            messagebox.showerror("Error", f"Failed to delete file:\n{file_path}")

    def _open_scan_file_location(self):
        selected = self.tree_scan.selection()
        if not selected:
            messagebox.showwarning("Open Location", "Please select a file from the scan table.")
            return

        item = self.tree_scan.item(selected[0])["values"]
        file_path = str(item[3])
        folder = os.path.dirname(file_path)
        if os.path.exists(folder):
            try:
                if os.name == "nt":
                    from src.core.proc_utils import popen_hidden
                    popen_hidden(["explorer.exe", f"/select,{os.path.normpath(file_path)}"])
                else:
                    os.startfile(folder)
            except Exception:
                pass

    def _dismiss_scan_selection(self):
        selected = self.tree_scan.selection()
        if selected:
            self.tree_scan.delete(selected[0])

    def _delete_quarantine_item(self):
        selected = self.tree_quarantine.selection()
        if not selected:
            messagebox.showwarning("Delete", "Please select a quarantined file to delete.")
            return

        item_values = self.tree_quarantine.item(selected[0])["values"]
        item_id = item_values[0]
        q_path = item_values[5]

        confirm = messagebox.askyesno("Confirm Permanent Deletion", f"Permanently remove this quarantined file?\n\n{q_path}\n\nWARNING: This cannot be undone!")
        if confirm:
            try:
                if os.path.exists(q_path):
                    os.remove(q_path)
                self.core.db_mgr.resolve_guardian_event(item_id, "deleted_from_quarantine")
                messagebox.showinfo("Deleted", "Quarantined file permanently removed.")
                self._load_quarantine_data()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete quarantined file: {e}")

    def for_each_clear_tree(self, tree):
        for item in tree.get_children():
            tree.delete(item)


class ControlCenterManager:
    """
    Manages opening and focusing the ControlCenter Tkinter GUI on a separate thread.
    Thread-safe and supports tab switching and real-time interactive alert dialogs.
    """

    def __init__(self, ghost_core):
        self.core = ghost_core
        self._app = None
        self._thread = None
        self._lock = threading.Lock()

    def show(self, initial_tab="overview"):
        with self._lock:
            if self._app and self._app.root and self._app.root.winfo_exists():
                self._app.root.after(0, lambda: self._focus_tab(initial_tab))
            else:
                self._thread = threading.Thread(
                    target=self._run_ui,
                    args=(initial_tab,),
                    name="ghost_control_center_thread",
                    daemon=True
                )
                self._thread.start()

    def _focus_tab(self, tab):
        if self._app and self._app.root and self._app.root.winfo_exists():
            self._app._select_tab(tab)
            self._app.root.deiconify()
            self._app.root.lift()
            self._app.root.focus_force()

    def _run_ui(self, initial_tab):
        try:
            self._app = ControlCenterApp(self.core, initial_tab=initial_tab)
            self._app.root.protocol("WM_DELETE_WINDOW", self._on_close)
            self._app.root.mainloop()
        except Exception as e:
            pass
        finally:
            with self._lock:
                self._app = None

    def _on_close(self):
        with self._lock:
            if self._app and self._app.root:
                try:
                    self._app.root.destroy()
                except Exception:
                    pass
                self._app = None

    def prompt_security_alert(self, event_id, file_path, reason, severity):
        """Displays an interactive alert popup asking user to Quarantine, Delete, or Let It Be (Ignore)."""
        def show_dialog():
            dialog = tk.Toplevel()
            dialog.title("👻 Ghost OS Security Alert")
            dialog.geometry("520x260")
            dialog.minsize(480, 240)
            dialog.configure(bg=BG_DARK)
            dialog.attributes("-topmost", True)
            dialog.lift()

            header = tk.Label(
                dialog,
                text="⚠ Suspicious / Unwanted File Detected",
                bg=BG_DARK,
                fg=ACCENT_RED,
                font=("Segoe UI", 12, "bold")
            )
            header.pack(anchor="w", padx=20, pady=(15, 5))

            msg_text = (
                f"File: {os.path.basename(file_path)}\n"
                f"Location: {file_path}\n"
                f"Risk: {severity}\n"
                f"Reason: {reason}\n\n"
                f"Choose an action to take:"
            )
            lbl = tk.Label(
                dialog,
                text=msg_text,
                bg=BG_DARK,
                fg=FG_MAIN,
                justify="left",
                font=("Segoe UI", 9)
            )
            lbl.pack(anchor="w", padx=20, pady=5)

            btn_frame = tk.Frame(dialog, bg=BG_DARK)
            btn_frame.pack(fill="x", padx=20, pady=(15, 10))

            def on_quarantine():
                dialog.destroy()
                self.core._handle_user_response(event_id, file_path, "quarantine")

            def on_delete():
                dialog.destroy()
                self.core._handle_user_response(event_id, file_path, "delete")

            def on_ignore():
                dialog.destroy()
                self.core._handle_user_response(event_id, file_path, "ignore")

            ttk.Button(btn_frame, text="🛡 Quarantine", style="Accent.TButton", command=on_quarantine).pack(side="left", padx=(0, 10))
            ttk.Button(btn_frame, text="🗑 Delete", style="Danger.TButton", command=on_delete).pack(side="left", padx=(0, 10))
            ttk.Button(btn_frame, text="✕ Let It Be (Ignore)", style="Secondary.TButton", command=on_ignore).pack(side="left")

        with self._lock:
            if self._app and self._app.root and self._app.root.winfo_exists():
                self._app.root.after(0, show_dialog)
            else:
                threading.Thread(target=lambda: self._run_standalone_alert(event_id, file_path, reason, severity), daemon=True).start()

    def _run_standalone_alert(self, event_id, file_path, reason, severity):
        try:
            root = tk.Tk()
            root.title("👻 Ghost OS Security Alert")
            root.geometry("520x260")
            root.minsize(480, 240)
            root.configure(bg=BG_DARK)
            root.attributes("-topmost", True)

            style = ttk.Style(root)
            style.theme_use("clam")
            style.configure("Accent.TButton", background=ACCENT_PURPLE, foreground="#ffffff", font=("Segoe UI", 9, "bold"), borderwidth=0, padding=6)
            style.configure("Danger.TButton", background=ACCENT_RED, foreground="#11111b", font=("Segoe UI", 9, "bold"), borderwidth=0, padding=6)
            style.configure("Secondary.TButton", background=BG_INPUT, foreground=FG_MAIN, font=("Segoe UI", 9), borderwidth=0, padding=6)

            header = tk.Label(root, text="⚠ Suspicious / Unwanted File Detected", bg=BG_DARK, fg=ACCENT_RED, font=("Segoe UI", 12, "bold"))
            header.pack(anchor="w", padx=20, pady=(15, 5))

            msg_text = (
                f"File: {os.path.basename(file_path)}\n"
                f"Location: {file_path}\n"
                f"Risk: {severity}\n"
                f"Reason: {reason}\n\n"
                f"Choose an action to take:"
            )
            lbl = tk.Label(root, text=msg_text, bg=BG_DARK, fg=FG_MAIN, justify="left", font=("Segoe UI", 9))
            lbl.pack(anchor="w", padx=20, pady=5)

            btn_frame = tk.Frame(root, bg=BG_DARK)
            btn_frame.pack(fill="x", padx=20, pady=(15, 10))

            def on_quarantine():
                root.destroy()
                self.core._handle_user_response(event_id, file_path, "quarantine")

            def on_delete():
                root.destroy()
                self.core._handle_user_response(event_id, file_path, "delete")

            def on_ignore():
                root.destroy()
                self.core._handle_user_response(event_id, file_path, "ignore")

            ttk.Button(btn_frame, text="🛡 Quarantine", style="Accent.TButton", command=on_quarantine).pack(side="left", padx=(0, 10))
            ttk.Button(btn_frame, text="🗑 Delete", style="Danger.TButton", command=on_delete).pack(side="left", padx=(0, 10))
            ttk.Button(btn_frame, text="✕ Let It Be (Ignore)", style="Secondary.TButton", command=on_ignore).pack(side="left")

            root.mainloop()
        except Exception:
            pass

