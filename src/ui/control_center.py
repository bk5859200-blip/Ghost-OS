import os
import sys
import time
import json
import logging
import traceback
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from src.core.path_manager import PathManager
from src.core.config_loader import load_config, ConfigError
from src.actions.scan_job import ManualScanJob
from src.actions.diagnostics_job import DiagnosticsJob

logger = logging.getLogger("ghost.ui.control_center")

# Modern Windows Security Dark Theme Color Palette
BG_DARK = "#11111b"       # Deep background
BG_SURFACE = "#181825"    # Surface panels
BG_CARD = "#1e1e2e"       # Card containers
BG_INPUT = "#313244"      # Input fields and progress troughs
BG_HOVER = "#45475a"      # Hover state

FG_MAIN = "#cdd6f4"       # Primary text
FG_MUTED = "#a6adc8"      # Secondary text
FG_DIM = "#6c7086"        # Disabled / subtle text

ACCENT_PURPLE = "#8c78ff" # Primary brand accent
ACCENT_BLUE = "#89b4fa"   # Information / telemetry
ACCENT_GREEN = "#a6e3a1"  # Success / Protected
ACCENT_YELLOW = "#f9e2af" # Warning / Attention
ACCENT_RED = "#f38ba8"    # Danger / Threat
ACCENT_PEACH = "#fab387"  # Paused / Maintenance


class ControlCenterApp:
    """
    Tkinter Native Control Center for Ghost OS.
    Features: Overview, Quick Scan, Security & Threats, Quarantine Vault,
    Activity History, Policy Settings, and System Diagnostics.
    """

    def __init__(self, ghost_core, initial_tab="overview"):
        self.core = ghost_core
        self.root = tk.Tk()
        self.root.title("Ghost OS — System Guardian 👻")
        self.root.geometry("960x680")
        self.root.minsize(840, 560)
        self.root.configure(bg=BG_DARK)

        self._active_scan_job = None
        self._activity_filter = "All"
        self._setup_styles()
        self._build_ui()
        self._select_tab(initial_tab)
        self._schedule_telemetry_update()

    def _setup_styles(self):
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")

        # Global Frame and Label defaults
        self.style.configure(".", background=BG_DARK, foreground=FG_MAIN, font=("Segoe UI", 9))
        self.style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        self.style.configure(
            "TNotebook.Tab",
            background=BG_SURFACE,
            foreground=FG_MUTED,
            padding=[14, 8],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0
        )
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT_PURPLE), ("active", BG_HOVER)],
            foreground=[("selected", "#ffffff"), ("active", FG_MAIN)]
        )

        # Card & Header styles
        self.style.configure("Card.TFrame", background=BG_CARD, relief="flat")
        self.style.configure("Surface.TFrame", background=BG_SURFACE, relief="flat")
        self.style.configure("Header.TLabel", background=BG_CARD, foreground=FG_MAIN, font=("Segoe UI", 12, "bold"))
        self.style.configure("Subheader.TLabel", background=BG_CARD, foreground=FG_MUTED, font=("Segoe UI", 9))
        self.style.configure("Value.TLabel", background=BG_CARD, foreground=ACCENT_BLUE, font=("Segoe UI", 15, "bold"))
        self.style.configure("StatusSuccess.TLabel", background=BG_CARD, foreground=ACCENT_GREEN, font=("Segoe UI", 11, "bold"))
        self.style.configure("StatusWarn.TLabel", background=BG_CARD, foreground=ACCENT_YELLOW, font=("Segoe UI", 11, "bold"))
        self.style.configure("StatusDanger.TLabel", background=BG_CARD, foreground=ACCENT_RED, font=("Segoe UI", 11, "bold"))

        # Buttons
        self.style.configure("Accent.TButton", background=ACCENT_PURPLE, foreground="#ffffff",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=7)
        self.style.map("Accent.TButton", background=[("active", "#7a66f0"), ("disabled", "#45475a")])

        self.style.configure("Secondary.TButton", background=BG_INPUT, foreground=FG_MAIN,
                             font=("Segoe UI", 9), borderwidth=0, padding=7)
        self.style.map("Secondary.TButton", background=[("active", BG_HOVER), ("disabled", "#24273a")])

        self.style.configure("Danger.TButton", background=ACCENT_RED, foreground="#11111b",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=7)
        self.style.map("Danger.TButton", background=[("active", "#e78284"), ("disabled", "#45475a")])

        # Filter Tag Buttons
        self.style.configure("FilterActive.TButton", background=ACCENT_PURPLE, foreground="#ffffff",
                             font=("Segoe UI", 8, "bold"), borderwidth=0, padding=4)
        self.style.configure("FilterInactive.TButton", background=BG_INPUT, foreground=FG_MUTED,
                             font=("Segoe UI", 8), borderwidth=0, padding=4)

        # Progressbar & Treeview
        self.style.configure("Accent.Horizontal.TProgressbar", background=ACCENT_PURPLE, troughcolor=BG_INPUT, borderwidth=0)
        self.style.configure("Treeview", background=BG_CARD, foreground=FG_MAIN,
                             fieldbackground=BG_CARD, borderwidth=0, rowheight=26, font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", background=BG_SURFACE, foreground=FG_MAIN,
                             font=("Segoe UI", 9, "bold"), relief="flat", padding=5)
        self.style.map("Treeview", background=[("selected", ACCENT_PURPLE)], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        # Header banner
        header_frame = tk.Frame(self.root, bg=BG_SURFACE, height=52)
        header_frame.pack(fill="x", side="top", padx=10, pady=(10, 6))

        title_frame = tk.Frame(header_frame, bg=BG_SURFACE)
        title_frame.pack(side="left", padx=15, pady=8)

        title_lbl = tk.Label(title_frame, text="👻 Ghost OS Background Guardian",
                             bg=BG_SURFACE, fg=FG_MAIN, font=("Segoe UI", 13, "bold"))
        title_lbl.pack(anchor="w")

        subtitle_lbl = tk.Label(title_frame, text="Local-first Windows system, file, and process guardian",
                                bg=BG_SURFACE, fg=FG_MUTED, font=("Segoe UI", 8))
        subtitle_lbl.pack(anchor="w")

        # Top State Badge
        self.state_badge = tk.Label(header_frame, text="🛡 PROTECTED",
                                    bg=ACCENT_GREEN, fg="#11111b", font=("Segoe UI", 9, "bold"), padx=10, pady=4)
        self.state_badge.pack(side="right", padx=15, pady=10)

        # Tab Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tab_overview = ttk.Frame(self.notebook)
        self.tab_scan = ttk.Frame(self.notebook)
        self.tab_threats = ttk.Frame(self.notebook)
        self.tab_quarantine = ttk.Frame(self.notebook)
        self.tab_activity = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        self.tab_diagnostics = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_overview, text="  Overview  ")
        self.notebook.add(self.tab_scan, text="  Quick Scan  ")
        self.notebook.add(self.tab_threats, text="  Threats & Alerts  ")
        self.notebook.add(self.tab_quarantine, text="  Quarantine Vault  ")
        self.notebook.add(self.tab_activity, text="  Activity Log  ")
        self.notebook.add(self.tab_settings, text="  Policy Settings  ")
        self.notebook.add(self.tab_diagnostics, text="  Diagnostics  ")

        self._build_overview_tab()
        self._build_scan_tab()
        self._build_threats_tab()
        self._build_quarantine_tab()
        self._build_activity_tab()
        self._build_settings_tab()
        self._build_diagnostics_tab()

    # ------------------------------------------------------------- 1. OVERVIEW TAB
    def _build_overview_tab(self):
        f = self.tab_overview

        # Main Protection Status Card
        status_card = ttk.Frame(f, style="Card.TFrame", padding=12)
        status_card.pack(fill="x", padx=10, pady=(10, 6))

        self.lbl_status_headline = ttk.Label(status_card, text="🛡 System Protected — Active Guardian Monitoring", style="StatusSuccess.TLabel")
        self.lbl_status_headline.pack(anchor="w")

        self.lbl_status_desc = ttk.Label(
            status_card,
            text="Continuous observation active across Downloads, Desktop, Temp, running processes, and telemetry.",
            style="Subheader.TLabel"
        )
        self.lbl_status_desc.pack(anchor="w", pady=(2, 0))

        # Metrics 2x4 Grid Frame
        metrics_frame = tk.Frame(f, bg=BG_DARK)
        metrics_frame.pack(fill="x", padx=10, pady=4)
        for col in range(4):
            metrics_frame.columnconfigure(col, weight=1)

        # Row 0: Real-time Telemetry
        # CPU
        c_cpu = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_cpu.grid(row=0, column=0, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_cpu, text="CPU Usage", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_cpu = ttk.Label(c_cpu, text="0.0%", style="Value.TLabel")
        self.lbl_cpu.pack(anchor="w", pady=2)

        # RAM
        c_ram = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_ram.grid(row=0, column=1, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_ram, text="RAM Usage", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_ram = ttk.Label(c_ram, text="0.0%", style="Value.TLabel")
        self.lbl_ram.pack(anchor="w", pady=2)

        # Disk
        c_disk = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_disk.grid(row=0, column=2, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_disk, text="Disk Usage (C:)", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_disk = ttk.Label(c_disk, text="0.0%", style="Value.TLabel")
        self.lbl_disk.pack(anchor="w", pady=2)

        # Mode
        c_mode = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_mode.grid(row=0, column=3, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_mode, text="Guardian Mode", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_mode = ttk.Label(c_mode, text="ACTIVE", style="Value.TLabel")
        self.lbl_mode.pack(anchor="w", pady=2)

        # Row 1: Guardian Scope & Security Stats
        # Monitored Folders
        c_folders = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_folders.grid(row=1, column=0, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_folders, text="Watch Folders", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_folders = ttk.Label(c_folders, text="5 Active", style="Value.TLabel")
        self.lbl_folders.pack(anchor="w", pady=2)

        # Monitored Processes
        c_procs = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_procs.grid(row=1, column=1, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_procs, text="Live Processes", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_procs = ttk.Label(c_procs, text="0", style="Value.TLabel")
        self.lbl_procs.pack(anchor="w", pady=2)

        # Threats Detected
        c_threats = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_threats.grid(row=1, column=2, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_threats, text="Threats Detected", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_threats_count = ttk.Label(c_threats, text="0", style="Value.TLabel")
        self.lbl_threats_count.pack(anchor="w", pady=2)

        # Quarantined Vault
        c_qvault = ttk.Frame(metrics_frame, style="Card.TFrame", padding=8)
        c_qvault.grid(row=1, column=3, padx=4, pady=4, sticky="nsew")
        ttk.Label(c_qvault, text="Quarantine Vault", style="Subheader.TLabel").pack(anchor="w")
        self.lbl_quarantine_count = ttk.Label(c_qvault, text="0 Items", style="Value.TLabel")
        self.lbl_quarantine_count.pack(anchor="w", pady=2)

        # Trend & Digest Row
        middle_row = tk.Frame(f, bg=BG_DARK)
        middle_row.pack(fill="both", expand=True, padx=10, pady=4)
        middle_row.columnconfigure(0, weight=1)
        middle_row.columnconfigure(1, weight=1)

        # Left: Sparkline Trend
        trend_frame = ttk.Frame(middle_row, style="Card.TFrame", padding=10)
        trend_frame.grid(row=0, column=0, padx=4, sticky="nsew")

        trend_hdr = tk.Frame(trend_frame, bg=BG_CARD)
        trend_hdr.pack(fill="x", pady=(0, 4))
        ttk.Label(trend_hdr, text="Telemetry Trend (Past 15m)", style="Subheader.TLabel").pack(side="left")
        ttk.Label(trend_hdr, text="■ RAM", foreground="#cba6f7", background=BG_CARD, font=("Segoe UI", 8, "bold")).pack(side="right", padx=(6, 0))
        ttk.Label(trend_hdr, text="■ CPU", foreground="#89b4fa", background=BG_CARD, font=("Segoe UI", 8, "bold")).pack(side="right", padx=(6, 0))

        self.canvas_trend = tk.Canvas(trend_frame, bg=BG_INPUT, height=65, highlightthickness=0)
        self.canvas_trend.pack(fill="both", expand=True)

        # Right: Activity Digest
        digest_frame = ttk.Frame(middle_row, style="Card.TFrame", padding=10)
        digest_frame.grid(row=0, column=1, padx=4, sticky="nsew")

        ttk.Label(digest_frame, text="Activity Digest (Past 24 Hours)", style="Subheader.TLabel").pack(anchor="w", pady=(0, 4))
        self.txt_digest = tk.Text(digest_frame, bg=BG_INPUT, fg=FG_MAIN, height=5,
                                  font=("Consolas", 8), relief="flat", padx=8, pady=6)
        self.txt_digest.pack(fill="both", expand=True)

        # Quick Actions Bar
        action_bar = tk.Frame(f, bg=BG_DARK)
        action_bar.pack(fill="x", padx=10, pady=(6, 10))

        ttk.Button(action_bar, text="▶ Run Quick Scan", style="Accent.TButton",
                   command=lambda: self._select_tab("scan")).pack(side="left", padx=(0, 8))
        ttk.Button(action_bar, text="🧹 Clean System", style="Secondary.TButton",
                   command=self._trigger_cleanup).pack(side="left", padx=(0, 8))
        self.btn_pause_toggle = ttk.Button(action_bar, text="⏸ Pause Guardian", style="Secondary.TButton",
                                            command=self._toggle_pause)
        self.btn_pause_toggle.pack(side="left", padx=(0, 8))
        ttk.Button(action_bar, text="⚡ Run Diagnostics", style="Secondary.TButton",
                   command=lambda: self._select_tab("diagnostics")).pack(side="left")

    # ------------------------------------------------------------- 2. QUICK SCAN TAB
    def _build_scan_tab(self):
        f = self.tab_scan

        ctrl_frame = ttk.Frame(f, style="Card.TFrame", padding=12)
        ctrl_frame.pack(fill="x", padx=10, pady=(10, 6))

        ttk.Label(ctrl_frame, text="On-Demand Security Scanner", style="Header.TLabel").pack(anchor="w")
        ttk.Label(ctrl_frame, text="Scans configured watch folders for disguised extensions, suspicious scripts, and malware via Rule Engine & Defender.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 8))

        btn_row = tk.Frame(ctrl_frame, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(0, 6))

        self.btn_start_scan = ttk.Button(btn_row, text="▶ Start Full Scan", style="Accent.TButton",
                                         command=self._start_scan_job)
        self.btn_start_scan.pack(side="left", padx=(0, 8))

        self.btn_cancel_scan = ttk.Button(btn_row, text="⏹ Cancel Scan", style="Danger.TButton",
                                          command=self._cancel_scan_job, state="disabled")
        self.btn_cancel_scan.pack(side="left")

        self.scan_progress = ttk.Progressbar(ctrl_frame, style="Accent.Horizontal.TProgressbar", mode="determinate")
        self.scan_progress.pack(fill="x", pady=6)

        self.lbl_scan_status = ttk.Label(ctrl_frame, text="Ready to scan.", style="Subheader.TLabel")
        self.lbl_scan_status.pack(anchor="w")

        # Results table
        results_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=4)

        ttk.Label(results_frame, text="Flagged Items & Threat Detections", style="Header.TLabel").pack(anchor="w", pady=(0, 4))

        columns = ("score", "severity", "category", "reason", "path")
        self.tree_scan = ttk.Treeview(results_frame, columns=columns, show="headings", selectmode="browse")
        self.tree_scan.heading("score", text="Score")
        self.tree_scan.heading("severity", text="Severity")
        self.tree_scan.heading("category", text="Category")
        self.tree_scan.heading("reason", text="Detection Reason")
        self.tree_scan.heading("path", text="File Path")

        self.tree_scan.column("score", width=70, anchor="center")
        self.tree_scan.column("severity", width=90, anchor="center")
        self.tree_scan.column("category", width=110, anchor="center")
        self.tree_scan.column("reason", width=260, anchor="w")
        self.tree_scan.column("path", width=380, anchor="w")

        scroll_scan = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree_scan.yview)
        self.tree_scan.configure(yscrollcommand=scroll_scan.set)

        self.tree_scan.pack(side="left", fill="both", expand=True)
        scroll_scan.pack(side="right", fill="y")

        # Scan results action buttons
        action_row = tk.Frame(f, bg=BG_DARK)
        action_row.pack(fill="x", padx=10, pady=(6, 10))

        ttk.Button(action_row, text="🛡 Quarantine Selected", style="Accent.TButton",
                   command=self._quarantine_scan_selection).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="🗑 Delete Selected", style="Danger.TButton",
                   command=self._delete_scan_selection).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="📁 Open Location", style="Secondary.TButton",
                   command=self._open_scan_file_location).pack(side="left", padx=(0, 8))
        ttk.Button(action_row, text="✕ Dismiss", style="Secondary.TButton",
                   command=self._dismiss_scan_selection).pack(side="left")

    # ------------------------------------------------------------- 3. THREATS & SECURITY TAB
    def _build_threats_tab(self):
        f = self.tab_threats

        top_frame = ttk.Frame(f, style="Card.TFrame", padding=12)
        top_frame.pack(fill="x", padx=10, pady=(10, 6))

        ttk.Label(top_frame, text="Security Detections & Alerts", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top_frame, text="All suspicious files, disguised executables, anomalous processes, and Defender detections.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 6))

        btn_row = tk.Frame(top_frame, bg=BG_CARD)
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="🔄 Refresh Detections", style="Secondary.TButton",
                   command=self._load_threats_data).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="🛡 Quarantine Selected", style="Accent.TButton",
                   command=self._quarantine_threat_selection).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="🗑 Delete Selected", style="Danger.TButton",
                   command=self._delete_threat_selection).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="📁 Open Location", style="Secondary.TButton",
                   command=self._open_threat_file_location).pack(side="left")

        # Threats Treeview
        table_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        table_frame.pack(fill="both", expand=True, padx=10, pady=4)

        cols = ("id", "date", "detector", "severity", "score", "status", "path")
        self.tree_threats = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_threats.heading("id", text="ID")
        self.tree_threats.heading("date", text="Date/Time")
        self.tree_threats.heading("detector", text="Source")
        self.tree_threats.heading("severity", text="Severity")
        self.tree_threats.heading("score", text="Score")
        self.tree_threats.heading("status", text="Status")
        self.tree_threats.heading("path", text="Target Path")

        self.tree_threats.column("id", width=40, anchor="center")
        self.tree_threats.column("date", width=140, anchor="center")
        self.tree_threats.column("detector", width=120, anchor="center")
        self.tree_threats.column("severity", width=90, anchor="center")
        self.tree_threats.column("score", width=60, anchor="center")
        self.tree_threats.column("status", width=90, anchor="center")
        self.tree_threats.column("path", width=380, anchor="w")

        scroll_t = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_threats.yview)
        self.tree_threats.configure(yscrollcommand=scroll_t.set)
        self.tree_threats.bind("<<TreeviewSelect>>", self._on_threat_selected)

        self.tree_threats.pack(side="left", fill="both", expand=True)
        scroll_t.pack(side="right", fill="y")

        # Threat Details Panel
        detail_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        detail_frame.pack(fill="x", padx=10, pady=(4, 10))

        ttk.Label(detail_frame, text="Detection Reason & Risk Signals:", style="Header.TLabel").pack(anchor="w")
        self.lbl_threat_detail = ttk.Label(detail_frame, text="Select an item above to view explainable risk signals.",
                                           style="Subheader.TLabel")
        self.lbl_threat_detail.pack(anchor="w", pady=(2, 0))

    # ------------------------------------------------------------- 4. QUARANTINE TAB
    def _build_quarantine_tab(self):
        f = self.tab_quarantine

        header_frame = ttk.Frame(f, style="Card.TFrame", padding=12)
        header_frame.pack(fill="x", padx=10, pady=(10, 6))

        ttk.Label(header_frame, text="Quarantine Vault", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="Safely isolated files. Restoring verifies SHA-256 integrity and returns the file to its original path.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 8))

        btn_row = tk.Frame(header_frame, bg=BG_CARD)
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="↺ Restore Selected File", style="Accent.TButton",
                   command=self._restore_quarantine_item).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="🗑 Permanently Delete", style="Danger.TButton",
                   command=self._delete_quarantine_item).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="📁 Open Vault Folder", style="Secondary.TButton",
                   command=self._open_quarantine_folder).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="🔄 Refresh", style="Secondary.TButton",
                   command=self._load_quarantine_data).pack(side="left")

        # Quarantine list
        table_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))

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
        self.tree_quarantine.column("orig_path", width=280, anchor="w")
        self.tree_quarantine.column("q_path", width=220, anchor="w")

        scroll_q = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_quarantine.yview)
        self.tree_quarantine.configure(yscrollcommand=scroll_q.set)

        self.tree_quarantine.pack(side="left", fill="both", expand=True)
        scroll_q.pack(side="right", fill="y")

    # ------------------------------------------------------------- 5. ACTIVITY HISTORY TAB
    def _build_activity_tab(self):
        f = self.tab_activity

        top_frame = ttk.Frame(f, style="Card.TFrame", padding=12)
        top_frame.pack(fill="x", padx=10, pady=(10, 6))

        ttk.Label(top_frame, text="Security & System Activity Log", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top_frame, text="Persistent audit trail of file events, process spawns, security detections, and maintenance.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 6))

        # Filter bar
        filter_bar = tk.Frame(top_frame, bg=BG_CARD)
        filter_bar.pack(fill="x", pady=(4, 0))

        ttk.Label(filter_bar, text="Filter:", style="Subheader.TLabel").pack(side="left", padx=(0, 6))

        self.filter_buttons = {}
        for cat in ("All", "Security", "Processes", "System", "Errors"):
            btn = ttk.Button(
                filter_bar,
                text=cat,
                style="FilterActive.TButton" if cat == "All" else "FilterInactive.TButton",
                command=lambda c=cat: self._set_activity_filter(c)
            )
            btn.pack(side="left", padx=2)
            self.filter_buttons[cat] = btn

        ttk.Button(filter_bar, text="🔄 Refresh Log", style="Secondary.TButton",
                   command=self._load_activity_data).pack(side="right")

        # Events table
        table_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        cols = ("time", "category", "severity", "source", "target", "reason")
        self.tree_activity = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_activity.heading("time", text="Timestamp")
        self.tree_activity.heading("category", text="Category")
        self.tree_activity.heading("severity", text="Severity")
        self.tree_activity.heading("source", text="Source")
        self.tree_activity.heading("target", text="Target File / Process")
        self.tree_activity.heading("reason", text="Reason / Details")

        self.tree_activity.column("time", width=140, anchor="center")
        self.tree_activity.column("category", width=90, anchor="center")
        self.tree_activity.column("severity", width=80, anchor="center")
        self.tree_activity.column("source", width=110, anchor="center")
        self.tree_activity.column("target", width=240, anchor="w")
        self.tree_activity.column("reason", width=280, anchor="w")

        scroll_act = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree_activity.yview)
        self.tree_activity.configure(yscrollcommand=scroll_act.set)

        self.tree_activity.pack(side="left", fill="both", expand=True)
        scroll_act.pack(side="right", fill="y")

    # ------------------------------------------------------------- 6. SETTINGS TAB
    def _build_settings_tab(self):
        f = self.tab_settings

        top_frame = ttk.Frame(f, style="Card.TFrame", padding=12)
        top_frame.pack(fill="x", padx=10, pady=(10, 6))

        ttk.Label(top_frame, text="Guardian Policy Editor (policy.yaml)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top_frame, text="Configurations are strictly validated against the policy schema before applying.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 6))

        btn_row = tk.Frame(top_frame, bg=BG_CARD)
        btn_row.pack(fill="x", pady=4)

        ttk.Button(btn_row, text="💾 Validate & Save Policy", style="Accent.TButton",
                   command=self._save_policy).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="↺ Reload From Disk", style="Secondary.TButton",
                   command=self._load_policy_file).pack(side="left", padx=(0, 8))

        self.lbl_policy_status = ttk.Label(top_frame, text="", style="Subheader.TLabel")
        self.lbl_policy_status.pack(anchor="w", pady=(4, 0))

        # Editor frame
        editor_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        editor_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        self.txt_policy = scrolledtext.ScrolledText(
            editor_frame, bg=BG_INPUT, fg=FG_MAIN, insertbackground=FG_MAIN,
            font=("Consolas", 10), relief="flat", padx=10, pady=10
        )
        self.txt_policy.pack(fill="both", expand=True)
        self._load_policy_file()

    # ------------------------------------------------------------- 7. DIAGNOSTICS TAB
    def _build_diagnostics_tab(self):
        f = self.tab_diagnostics

        top_frame = ttk.Frame(f, style="Card.TFrame", padding=12)
        top_frame.pack(fill="x", padx=10, pady=(10, 6))

        ttk.Label(top_frame, text="Subsystem Health & Diagnostics", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top_frame, text="Executes end-to-end verification across Defender CLI, Database, Sensors, Storage, and Watchers.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(2, 6))

        self.btn_run_diag = ttk.Button(top_frame, text="⚡ Run Full Diagnostics", style="Accent.TButton",
                                       command=self._trigger_diagnostics)
        self.btn_run_diag.pack(anchor="w", pady=4)

        # Output text area
        diag_frame = ttk.Frame(f, style="Card.TFrame", padding=10)
        diag_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        self.txt_diagnostics = scrolledtext.ScrolledText(
            diag_frame, bg=BG_INPUT, fg=FG_MAIN, font=("Consolas", 9),
            relief="flat", padx=10, pady=10
        )
        self.txt_diagnostics.pack(fill="both", expand=True)
        self.txt_diagnostics.insert("1.0", "Click 'Run Full Diagnostics' to evaluate all subsystems.\n")

    # ------------------------------------------------------------- LOGIC & ACTIONS
    def _select_tab(self, tab_name):
        mapping = {
            "overview": self.tab_overview,
            "scan": self.tab_scan,
            "threats": self.tab_threats,
            "quarantine": self.tab_quarantine,
            "activity": self.tab_activity,
            "policy": self.tab_settings,
            "settings": self.tab_settings,
            "diagnostics": self.tab_diagnostics
        }
        target = mapping.get(str(tab_name).lower(), self.tab_overview)
        self.notebook.select(target)
        if str(tab_name).lower() == "threats":
            self._load_threats_data()
        elif str(tab_name).lower() == "quarantine":
            self._load_quarantine_data()
        elif str(tab_name).lower() == "activity":
            self._load_activity_data()

    def _schedule_telemetry_update(self):
        try:
            if not self.root or not self.root.winfo_exists():
                return
            self._update_overview_telemetry()
            if self.root and self.root.winfo_exists():
                self.root.after(2000, self._schedule_telemetry_update)
        except Exception as e:
            logger.debug(f"Telemetry update loop stopped: {e}")

    def _update_overview_telemetry(self):
        try:
            state = self.core.get_health_state()
            is_paused = self.core._pause_event.is_set()

            # State badge & headline
            if is_paused or state == "PAUSED":
                self.state_badge.config(text="⏸ PAUSED", bg=ACCENT_PEACH, fg="#11111b")
                self.lbl_status_headline.config(text="⏸ Protection Paused — Guardian Is Idle", style="StatusWarn.TLabel")
                self.lbl_status_desc.config(text="Monitoring is temporarily paused. Background watchers are not scanning.")
                self.lbl_mode.config(text="PAUSED", foreground=ACCENT_PEACH)
            elif state in ("PROTECTING", "ATTENTION"):
                self.state_badge.config(text="⚠ ATTENTION", bg=ACCENT_YELLOW, fg="#11111b")
                self.lbl_status_headline.config(text="⚠ Potential Security Attention Recommended", style="StatusWarn.TLabel")
                self.lbl_status_desc.config(text="Recent suspicious events or resource anomalies were recorded.")
                self.lbl_mode.config(text="ACTIVE", foreground=ACCENT_YELLOW)
            elif state == "ERROR":
                self.state_badge.config(text="❌ ERROR", bg=ACCENT_RED, fg="#11111b")
                self.lbl_status_headline.config(text="❌ Subsystem Error Detected", style="StatusDanger.TLabel")
                self.lbl_status_desc.config(text="Check Diagnostics tab for details on failing components.")
                self.lbl_mode.config(text="ERROR", foreground=ACCENT_RED)
            else:
                self.state_badge.config(text="🛡 PROTECTED", bg=ACCENT_GREEN, fg="#11111b")
                self.lbl_status_headline.config(text="🛡 System Protected — Active Guardian Monitoring", style="StatusSuccess.TLabel")
                self.lbl_status_desc.config(text="Continuous observation active across Downloads, Desktop, Temp, processes, and telemetry.")
                self.lbl_mode.config(text="ACTIVE", foreground=ACCENT_GREEN)

            self.btn_pause_toggle.config(text="▶ Resume Guardian" if is_paused else "⏸ Pause Guardian")

            # Sensors
            if hasattr(self.core, "sensor"):
                metrics = self.core.sensor.collect_metrics()
                self.lbl_cpu.config(text=f"{metrics.get('cpu_percent', 0.0):.1f}%")
                self.lbl_ram.config(text=f"{metrics.get('ram_percent', 0.0):.1f}%")
                self.lbl_disk.config(text=f"{metrics.get('disk_used_percent', 0.0):.1f}% ({metrics.get('disk_free_gb', 0.0)} GB free)")
                self.lbl_procs.config(text=str(metrics.get("process_count", 0)))

            # Folder count
            watch_folders = getattr(self.core.file_watcher, "raw_folders", [])
            self.lbl_folders.config(text=f"{len(watch_folders)} Active")

            # Digest summary & counts
            summary = self.core.get_away_summary(window_hours=24)
            self.lbl_threats_count.config(text=str(summary.get("suspicious_count", 0)))
            self.lbl_quarantine_count.config(text=f"{summary.get('quarantined_count', 0)} Items")

            digest_text = (
                f"Assessment:         {summary['status_assessment']}\n"
                f"Suspicious Events:  {summary['suspicious_count']}\n"
                f"Quarantined Files:  {summary['quarantined_count']}\n"
                f"Process Launches:   {summary['process_starts_count']}\n"
                f"Anomalies Logged:   {summary['anomalies_count']}\n"
                f"Space Recovered:    {summary['space_recovered_mb']} MB ({summary['cleanups_count']} cleanup runs)"
            )
            self.txt_digest.delete("1.0", "end")
            self.txt_digest.insert("1.0", digest_text)

            # Sparkline trend
            self._draw_sparkline()
        except Exception as e:
            logger.debug(f"Telemetry update error: {e}")

    def _draw_sparkline(self):
        try:
            if not hasattr(self, "canvas_trend") or not self.canvas_trend.winfo_exists():
                return
            metrics_history = self.core.db_mgr.get_latest_system_metrics(limit=45)
            self.canvas_trend.delete("all")
            w = self.canvas_trend.winfo_width()
            h = self.canvas_trend.winfo_height()
            if w <= 10 or h <= 10:
                w, h = 400, 65

            # Background grid lines (25%, 50%, 75%)
            for pct in (0.25, 0.50, 0.75):
                y = h - (pct * h)
                self.canvas_trend.create_line(0, y, w, y, fill="#282a36", dash=(2, 4))

            if not metrics_history or len(metrics_history) < 2:
                return

            n = len(metrics_history)
            dx = w / max(n - 1, 1)

            cpu_pts = []
            ram_pts = []
            for i, m in enumerate(metrics_history):
                x = i * dx
                cpu_val = min(max(m.get("cpu_percent", 0.0), 0.0), 100.0)
                ram_val = min(max(m.get("ram_percent", 0.0), 0.0), 100.0)
                y_cpu = (h - 4) - (cpu_val / 100.0 * (h - 8))
                y_ram = (h - 4) - (ram_val / 100.0 * (h - 8))
                cpu_pts.extend([x, y_cpu])
                ram_pts.extend([x, y_ram])

            if len(cpu_pts) >= 4:
                self.canvas_trend.create_line(*cpu_pts, fill="#89b4fa", width=2, smooth=True)
            if len(ram_pts) >= 4:
                self.canvas_trend.create_line(*ram_pts, fill="#cba6f7", width=2, smooth=True)
        except Exception as e:
            logger.debug(f"Sparkline render error: {e}")

    def _toggle_pause(self):
        if self.core._pause_event.is_set():
            self.core.resume()
        else:
            self.core.pause()
        self._update_overview_telemetry()

    def _trigger_cleanup(self):
        self.core.propose_cleanup()
        messagebox.showinfo("Ghost OS Cleanup", "System cleanup preview initiated in background.")

    # ------------------------------------------------------------- Quick Scan Logic
    def _start_scan_job(self):
        if self._active_scan_job and self._active_scan_job.is_running:
            messagebox.showinfo("Scan In Progress", "A system scan is already running.")
            return

        self.for_each_clear_tree(self.tree_scan)
        self.scan_progress["value"] = 0
        self.btn_start_scan.config(state="disabled")
        self.btn_cancel_scan.config(state="normal")
        self.lbl_scan_status.config(text="Initializing file discovery...")

        def on_prog(cur, total, path):
            pct = (cur / total * 100.0) if total > 0 else 0
            self.root.after(0, lambda: self._update_scan_progress(pct, cur, total, path))

        def on_done(res):
            self.root.after(0, lambda: self._on_scan_finished(res))

        self._active_scan_job = self.core.create_manual_scan(on_progress=on_prog, on_complete=on_done)
        self._active_scan_job.start()

    def _update_scan_progress(self, pct, cur, total, path):
        self.scan_progress["value"] = pct
        short_name = os.path.basename(path)
        self.lbl_scan_status.config(text=f"Scanning ({cur}/{total}): {short_name}")

    def _on_scan_finished(self, res):
        self.scan_progress["value"] = 100
        self.btn_start_scan.config(state="normal")
        self.btn_cancel_scan.config(state="disabled")

        if res.get("error"):
            self.lbl_scan_status.config(text=f"Scan error: {res['error']}")
            return

        flagged = res.get("flagged_items", [])
        status_msg = f"Scan complete. {res.get('scanned_count', 0)} files scanned in {res.get('duration_seconds', 0)}s. {len(flagged)} threat(s) found."
        self.lbl_scan_status.config(text=status_msg)

        for item in flagged:
            self.tree_scan.insert("", "end", values=(
                item.get("risk_score"),
                item.get("classification"),
                item.get("category"),
                item.get("reason", "Suspicious file characteristics"),
                item.get("file_path")
            ))

    def _cancel_scan_job(self):
        if self._active_scan_job:
            self._active_scan_job.cancel()
            self.lbl_scan_status.config(text="Cancelling scan...")

    def _quarantine_scan_selection(self):
        selected = self.tree_scan.selection()
        if not selected:
            messagebox.showwarning("Quarantine", "Please select a flagged file from the scan table to quarantine.")
            return

        item = self.tree_scan.item(selected[0])["values"]
        file_path = str(item[4])
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
            self._load_threats_data()
        else:
            messagebox.showerror("Error", f"Failed to quarantine file:\n{file_path}")

    def _delete_scan_selection(self):
        selected = self.tree_scan.selection()
        if not selected:
            messagebox.showwarning("Delete", "Please select a flagged file from the scan table to delete.")
            return

        item = self.tree_scan.item(selected[0])["values"]
        file_path = str(item[4])
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
            self._load_threats_data()
        else:
            messagebox.showerror("Error", f"Failed to delete file:\n{file_path}")

    def _open_scan_file_location(self):
        selected = self.tree_scan.selection()
        if not selected:
            messagebox.showwarning("Open Location", "Please select a file from the scan table.")
            return

        item = self.tree_scan.item(selected[0])["values"]
        file_path = str(item[4])
        self._open_file_in_explorer(file_path)

    def _dismiss_scan_selection(self):
        selected = self.tree_scan.selection()
        if selected:
            self.tree_scan.delete(selected[0])

    # ------------------------------------------------------------- Threats & Security Logic
    def _load_threats_data(self):
        self.for_each_clear_tree(self.tree_threats)
        try:
            events = self.core.db_mgr.get_recent_events(limit=100)
            for ev in events:
                self.tree_threats.insert("", "end", values=(
                    ev.get("id"),
                    ev.get("timestamp"),
                    ev.get("detector"),
                    ev.get("severity"),
                    ev.get("risk_score", 0),
                    ev.get("status", "pending"),
                    ev.get("file_path")
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load threat events: {e}")

    def _on_threat_selected(self, event):
        selected = self.tree_threats.selection()
        if not selected:
            return
        item = self.tree_threats.item(selected[0])["values"]
        ev_id = item[0]
        try:
            conn = self.core.db_mgr.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT reason, signals_json FROM guardian_events WHERE id = ?", (ev_id,))
            row = cursor.fetchone()
            if row:
                reason = row["reason"]
                signals_raw = row["signals_json"]
                signals_text = ""
                if signals_raw:
                    try:
                        sigs = json.loads(signals_raw)
                        signals_text = "Signals: " + ", ".join(f"+{s.get('points')} {s.get('reason')}" for s in sigs)
                    except Exception:
                        pass
                detail_str = f"Reason: {reason}\n{signals_text}" if signals_text else f"Reason: {reason}"
                self.lbl_threat_detail.config(text=detail_str)
        except Exception as e:
            logger.debug(f"Error fetching threat details: {e}")

    def _quarantine_threat_selection(self):
        selected = self.tree_threats.selection()
        if not selected:
            messagebox.showwarning("Quarantine", "Please select a detection to quarantine.")
            return
        item = self.tree_threats.item(selected[0])["values"]
        event_id = item[0]
        file_path = str(item[6])

        if not os.path.exists(file_path):
            messagebox.showerror("Error", f"Target file no longer exists:\n{file_path}")
            return

        confirm = messagebox.askyesno("Confirm Quarantine", f"Quarantine this file?\n\n{file_path}")
        if confirm:
            allowed, reason = self.core.safety.gate_action("quarantine", file_path)
            if not allowed:
                if reason == "dry_run":
                    messagebox.showinfo("Dry Run", "Dry Run mode active. Quarantine simulated.")
                else:
                    messagebox.showerror("Blocked", f"Blocked by Safety Engine: {reason}")
                return
            success, dest, _ = self.core.quarantine.quarantine_file(event_id, file_path)
            if success:
                messagebox.showinfo("Quarantined", f"File safely moved to:\n{dest}")
                self._load_threats_data()
                self._load_quarantine_data()

    def _delete_threat_selection(self):
        selected = self.tree_threats.selection()
        if not selected:
            messagebox.showwarning("Delete", "Please select a detection to delete.")
            return
        item = self.tree_threats.item(selected[0])["values"]
        event_id = item[0]
        file_path = str(item[6])

        if not os.path.exists(file_path):
            messagebox.showerror("Error", f"Target file no longer exists:\n{file_path}")
            return

        confirm = messagebox.askyesno("Confirm Deletion", f"Permanently delete this file?\n\n{file_path}\n\nWARNING: This cannot be undone!")
        if confirm:
            allowed, reason = self.core.safety.gate_action("delete", file_path)
            if not allowed:
                if reason == "dry_run":
                    messagebox.showinfo("Dry Run", "Dry Run mode active. Deletion simulated.")
                else:
                    messagebox.showerror("Blocked", f"Blocked by Safety Engine: {reason}")
                return
            if self.core.quarantine.delete_file(event_id, file_path):
                messagebox.showinfo("Deleted", f"File deleted:\n{file_path}")
                self._load_threats_data()

    def _open_threat_file_location(self):
        selected = self.tree_threats.selection()
        if not selected:
            messagebox.showwarning("Open Location", "Please select a detection from the table.")
            return
        item = self.tree_threats.item(selected[0])["values"]
        file_path = str(item[6])
        self._open_file_in_explorer(file_path)

    # ------------------------------------------------------------- Quarantine Logic
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
                self._load_threats_data()
            else:
                messagebox.showerror("Failed", f"Failed to restore file from:\n{q_path}")

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
                self._load_threats_data()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete quarantined file: {e}")

    def _open_quarantine_folder(self):
        q_dir = self.core.quarantine.quarantine_dir
        self._open_file_in_explorer(q_dir, is_dir=True)

    # ------------------------------------------------------------- Activity History Logic
    def _set_activity_filter(self, category):
        self._activity_filter = category
        for cat, btn in self.filter_buttons.items():
            btn.configure(style="FilterActive.TButton" if cat == category else "FilterInactive.TButton")
        self._load_activity_data()

    def _load_activity_data(self):
        self.for_each_clear_tree(self.tree_activity)
        try:
            self.core.db_mgr.flush()
            conn = self.core.db_mgr.get_connection()
            cursor = conn.cursor()

            # Gather events across guardian_events, process_events, and cleanup_events
            items = []

            # 1. Security events
            if self._activity_filter in ("All", "Security"):
                cursor.execute("SELECT timestamp, 'Security' as cat, severity, detector as src, file_path as target, reason FROM guardian_events ORDER BY id DESC LIMIT 50")
                for r in cursor.fetchall():
                    items.append(dict(r))

            # 2. Process events
            if self._activity_filter in ("All", "Processes"):
                cursor.execute("SELECT timestamp, 'Process' as cat, CASE WHEN anomaly_flag=1 THEN 'HIGH' ELSE 'INFO' END as severity, 'ProcessWatcher' as src, name as target, 'Process ' || event_type as reason FROM process_events ORDER BY id DESC LIMIT 50")
                for r in cursor.fetchall():
                    items.append(dict(r))

            # 3. System / Cleanup events
            if self._activity_filter in ("All", "System"):
                cursor.execute("SELECT timestamp, 'Cleanup' as cat, 'INFO' as severity, 'SystemCleaner' as src, 'Temp Folders' as target, 'Recovered ' || space_recovered_mb || ' MB (' || files_removed || ' files)' as reason FROM cleanup_events ORDER BY id DESC LIMIT 30")
                for r in cursor.fetchall():
                    items.append(dict(r))

            # 4. Anomalies
            if self._activity_filter in ("All", "Errors"):
                cursor.execute("SELECT timestamp, 'Anomaly' as cat, 'WARN' as severity, source as src, entity_name as target, description as reason FROM anomalies ORDER BY id DESC LIMIT 30")
                for r in cursor.fetchall():
                    items.append(dict(r))

            # Sort combined by timestamp descending
            items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            for ev in items[:80]:
                self.tree_activity.insert("", "end", values=(
                    ev.get("timestamp"),
                    ev.get("cat"),
                    ev.get("severity"),
                    ev.get("src"),
                    ev.get("target"),
                    ev.get("reason")
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load activity events: {e}")

    # ------------------------------------------------------------- Settings Logic
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

    # ------------------------------------------------------------- Diagnostics Logic
    def _trigger_diagnostics(self):
        if getattr(self, "_diag_running", False):
            messagebox.showinfo("Diagnostics In Progress", "Diagnostics checklist is already running.")
            return

        self._diag_running = True
        self.btn_run_diag.config(state="disabled")
        self.txt_diagnostics.delete("1.0", "end")
        self.txt_diagnostics.insert("1.0", "Running system diagnostics checklist...\n")

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

    # ------------------------------------------------------------- Utilities
    def _open_file_in_explorer(self, target_path, is_dir=False):
        try:
            if sys.platform == "win32":
                from src.core.proc_utils import popen_hidden
                if is_dir or os.path.isdir(target_path):
                    popen_hidden(["explorer.exe", os.path.normpath(target_path)])
                else:
                    popen_hidden(["explorer.exe", f"/select,{os.path.normpath(target_path)}"])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", os.path.dirname(target_path) if not is_dir else target_path])
        except Exception as e:
            logger.error(f"Failed to open explorer for {target_path}: {e}")

    def for_each_clear_tree(self, tree):
        for item in tree.get_children():
            tree.delete(item)


class ControlCenterManager:
    """
    Authoritative manager for the Control Center Tkinter GUI on the main thread.
    Thread-safe, supporting tab switching, hide/restore to system tray,
    and interactive alert dialogs with single-root ownership.
    """

    def __init__(self, ghost_core):
        self.core = ghost_core
        self._app = None
        self._lock = threading.Lock()

    def start_main_loop(self, initial_tab="overview"):
        """
        Initializes and runs the Control Center Tkinter mainloop on the calling (main) thread.
        Displays the window immediately.
        """
        try:
            logger.info(f"Initializing Control Center on thread: {threading.current_thread().name}")
            with self._lock:
                self._app = ControlCenterApp(self.core, initial_tab=initial_tab)
                self._app.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
                self._app.root.deiconify()
                self._app.root.lift()
                self._app.root.focus_force()

            logger.info("Control Center main loop starting.")
            self._app.root.mainloop()
            logger.info("Control Center main loop ended.")
        except Exception as e:
            exc_type, exc_val, exc_tb = sys.exc_info()
            thread_name = threading.current_thread().name
            logger.critical(
                f"Control Center encountered an unhandled exception during UI execution:\n"
                f"Type: {exc_type.__name__ if exc_type else 'Unknown'}\n"
                f"Message: {exc_val}\n"
                f"Thread: {thread_name}\n"
                f"State: {self.core.get_health_state()}\n"
                f"Traceback:\n{''.join(traceback.format_exception(exc_type, exc_val, exc_tb))}"
            )
            raise
        finally:
            with self._lock:
                self._app = None

    def show(self, initial_tab="overview"):
        """
        Thread-safe method to restore and bring the existing Control Center window to the front.
        If the window is hidden/minimized, it restores it without creating duplicate roots.
        """
        with self._lock:
            if self._app and self._app.root:
                try:
                    if self._app.root.winfo_exists():
                        self._app.root.after(0, lambda: self._focus_tab(initial_tab))
                        return
                except Exception as e:
                    logger.warning(f"Error checking root window state: {e}")

        logger.debug(f"Control Center show({initial_tab}) requested but UI root is not active.")

    def _focus_tab(self, tab):
        """Executed on main thread via root.after()."""
        try:
            if self._app and self._app.root and self._app.root.winfo_exists():
                self._app._select_tab(tab)
                self._app.root.deiconify()
                if self._app.root.state() == "iconic":
                    self._app.root.state("normal")
                self._app.root.lift()
                self._app.root.focus_force()
        except Exception as e:
            logger.error(f"Failed to focus tab '{tab}': {e}", exc_info=True)

    def _on_window_close(self):
        """
        When user clicks the 'X' button, hide to tray instead of destroying the application.
        Background monitoring and tray continue running.
        """
        with self._lock:
            if self._app and self._app.root:
                try:
                    if self._app.root.winfo_exists():
                        self._app.root.withdraw()
                        logger.info("Control Center window hidden to system tray.")
                except Exception as e:
                    logger.error(f"Error hiding window to tray: {e}", exc_info=True)

    def exit_app(self):
        """
        Cleanly destroys the Tkinter UI and breaks the mainloop for application shutdown.
        Can be safely invoked from tray or background threads.
        """
        with self._lock:
            if self._app and self._app.root:
                try:
                    if self._app.root.winfo_exists():
                        self._app.root.after(0, self._destroy_ui)
                except Exception as e:
                    logger.error(f"Error scheduling UI destruction: {e}", exc_info=True)

    def _destroy_ui(self):
        """Executed on the main thread."""
        try:
            if self._app and self._app.root and self._app.root.winfo_exists():
                logger.info("Destroying Control Center Tkinter root window.")
                self._app.root.destroy()
        except Exception as e:
            logger.error(f"Error destroying Tkinter root: {e}", exc_info=True)
        finally:
            self._app = None

    def prompt_security_alert(self, event_id, file_path, reason, severity):
        """Displays an interactive alert popup asking user to Quarantine, Delete, or Let It Be (Ignore)."""
        def show_dialog():
            try:
                parent = self._app.root if (self._app and self._app.root and self._app.root.winfo_exists()) else None
                dialog = tk.Toplevel(parent) if parent else tk.Tk()
                dialog.title("👻 Ghost OS Security Alert")
                dialog.geometry("540x270")
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
                    f"Assessment: {severity}\n"
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

                if not parent:
                    dialog.mainloop()
            except Exception as e:
                exc_type, exc_val, exc_tb = sys.exc_info()
                logger.error(
                    f"Failed to display security alert dialog: {exc_type.__name__ if exc_type else 'Unknown'}: {exc_val}\n"
                    f"Traceback:\n{''.join(traceback.format_exception(exc_type, exc_val, exc_tb))}"
                )

        with self._lock:
            if self._app and self._app.root and self._app.root.winfo_exists():
                self._app.root.after(0, show_dialog)
            else:
                threading.Thread(target=show_dialog, name="ghost_alert_thread", daemon=True).start()


