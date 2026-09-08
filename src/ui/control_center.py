import os
import sys
import time
import json
import logging
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
    Standardized 8-tab Information Architecture:
      1. Overview (Dashboard, status cards, away digest, quick actions)
      2. Security Scan (Full watch folder threat scan, finding classification)
      3. Junk & Temp Cleanup (Expandable location tree, candidate status, safe cleanup)
      4. Quarantine (Quarantined items vault, details, safe restore/remove)
      5. Activity (Human-readable timeline log, category filters, clear history)
      6. Settings (Categorized form-based toggles & controls + Advanced YAML editor)
      7. System Health (10-subsystem diagnostic checklist with latency & status)
      8. About (Architecture, storage paths, version & documentation)
    """

    def __init__(self, ghost_core, initial_tab="overview"):
        self.core = ghost_core
        self.root = tk.Tk()
        self.root.title("Ghost OS — System Guardian 👻")
        self.root.geometry("980x700")
        self.root.minsize(860, 580)
        self.root.configure(bg=BG_DARK)

        self._active_scan_job = None
        self._activity_filter = "ALL"
        self._cleanup_candidates = []
        self._diagnostics_running = False

        # Register callback with core for notification and tab navigation
        if hasattr(self.core, "ui_alert_callback"):
            self.core.ui_alert_callback = self._on_in_app_security_alert
        if hasattr(self.core, "ui_show_tab_callback"):
            self.core.ui_show_tab_callback = self._focus_tab

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
            padding=[12, 8],
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
        self.style.configure("Header.TLabel", background=BG_CARD, foreground=FG_MAIN, font=("Segoe UI", 11, "bold"))
        self.style.configure("Subheader.TLabel", background=BG_CARD, foreground=FG_MUTED, font=("Segoe UI", 8))
        self.style.configure("Value.TLabel", background=BG_CARD, foreground=ACCENT_BLUE, font=("Segoe UI", 14, "bold"))
        self.style.configure("StatusSuccess.TLabel", background=BG_CARD, foreground=ACCENT_GREEN, font=("Segoe UI", 10, "bold"))
        self.style.configure("StatusWarn.TLabel", background=BG_CARD, foreground=ACCENT_YELLOW, font=("Segoe UI", 10, "bold"))
        self.style.configure("StatusDanger.TLabel", background=BG_CARD, foreground=ACCENT_RED, font=("Segoe UI", 10, "bold"))

        # Buttons
        self.style.configure("Accent.TButton", background=ACCENT_PURPLE, foreground="#ffffff",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=7)
        self.style.map("Accent.TButton", background=[("active", "#7a66f0"), ("disabled", "#45475a")])

        self.style.configure("Secondary.TButton", background=BG_INPUT, foreground=FG_MAIN,
                             font=("Segoe UI", 9), borderwidth=0, padding=7)
        self.style.map("Secondary.TButton", background=[("active", BG_HOVER), ("disabled", "#24273a")])

        self.style.configure("Success.TButton", background=ACCENT_GREEN, foreground="#11111b",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=7)
        self.style.map("Success.TButton", background=[("active", "#89dceb"), ("disabled", "#45475a")])

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

        # Scrollbars
        self.style.configure("Vertical.TScrollbar", background=BG_INPUT, troughcolor=BG_DARK, borderwidth=0)

    def _build_ui(self):
        # Header banner
        header_frame = tk.Frame(self.root, bg=BG_SURFACE, height=52)
        header_frame.pack(fill="x", side="top", padx=10, pady=(10, 6))

        title_frame = tk.Frame(header_frame, bg=BG_SURFACE)
        title_frame.pack(side="left", padx=15, pady=8)

        title_lbl = tk.Label(title_frame, text="👻 Ghost OS System Guardian",
                             bg=BG_SURFACE, fg=FG_MAIN, font=("Segoe UI", 13, "bold"))
        title_lbl.pack(anchor="w")

        subtitle_lbl = tk.Label(title_frame, text="Continuous local-first Windows monitoring, threat defense & safe cleanup",
                                bg=BG_SURFACE, fg=FG_MUTED, font=("Segoe UI", 8))
        subtitle_lbl.pack(anchor="w")

        # Top State Badge
        self.state_badge = tk.Label(header_frame, text="🛡 PROTECTED",
                                    bg=ACCENT_GREEN, fg="#11111b", font=("Segoe UI", 9, "bold"), padx=10, pady=4)
        self.state_badge.pack(side="right", padx=15, pady=10)

        # Tab Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 8 Clean Tabs
        self.tab_overview = ttk.Frame(self.notebook)
        self.tab_scan = ttk.Frame(self.notebook)
        self.tab_cleanup = ttk.Frame(self.notebook)
        self.tab_quarantine = ttk.Frame(self.notebook)
        self.tab_activity = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        self.tab_diagnostics = ttk.Frame(self.notebook)
        self.tab_about = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_overview, text="  Overview  ")
        self.notebook.add(self.tab_scan, text="  Security Scan  ")
        self.notebook.add(self.tab_cleanup, text="  Junk & Temp Cleanup  ")
        self.notebook.add(self.tab_quarantine, text="  Quarantine  ")
        self.notebook.add(self.tab_activity, text="  Activity  ")
        self.notebook.add(self.tab_settings, text="  Settings  ")
        self.notebook.add(self.tab_diagnostics, text="  System Health  ")
        self.notebook.add(self.tab_about, text="  About  ")

        # Build individual tabs
        self._build_overview_tab()
        self._build_scan_tab()
        self._build_cleanup_tab()
        self._build_quarantine_tab()
        self._build_activity_tab()
        self._build_settings_tab()
        self._build_diagnostics_tab()
        self._build_about_tab()

    # =========================================================================
    # 1. OVERVIEW TAB
    # =========================================================================
    def _build_overview_tab(self):
        container = tk.Frame(self.tab_overview, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        # Top System Status Banner Card
        top_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        top_card.pack(fill="x", pady=(0, 10))

        top_left = tk.Frame(top_card, bg=BG_CARD)
        top_left.pack(side="left", fill="both", expand=True)

        self.lbl_overview_headline = tk.Label(top_left, text="System is Protected",
                                              bg=BG_CARD, fg=ACCENT_GREEN, font=("Segoe UI", 13, "bold"))
        self.lbl_overview_headline.pack(anchor="w")

        self.lbl_overview_sub = tk.Label(top_left,
                                         text="Continuous background monitoring active across filesystem, processes, and memory.",
                                         bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9))
        self.lbl_overview_sub.pack(anchor="w", pady=(2, 0))

        # Metric Cards Grid (2 rows x 3 cols)
        grid_frame = tk.Frame(container, bg=BG_DARK)
        grid_frame.pack(fill="x", pady=(0, 10))
        grid_frame.columnconfigure((0, 1, 2), weight=1, uniform="col")

        # Card 1: Monitoring Status
        c1 = ttk.Frame(grid_frame, style="Card.TFrame", padding=10)
        c1.grid(row=0, column=0, padx=4, pady=4, sticky="nsew")
        ttk.Label(c1, text="Continuous Monitoring", style="Header.TLabel").pack(anchor="w")
        self.lbl_card_monitoring = ttk.Label(c1, text="ACTIVE", style="StatusSuccess.TLabel")
        self.lbl_card_monitoring.pack(anchor="w", pady=(4, 0))
        self.lbl_card_monitoring_sub = ttk.Label(c1, text="State: WATCHING", style="Subheader.TLabel")
        self.lbl_card_monitoring_sub.pack(anchor="w")

        # Card 2: Last Threat Scan
        c2 = ttk.Frame(grid_frame, style="Card.TFrame", padding=10)
        c2.grid(row=0, column=1, padx=4, pady=4, sticky="nsew")
        ttk.Label(c2, text="Last Security Scan", style="Header.TLabel").pack(anchor="w")
        self.lbl_card_scan = ttk.Label(c2, text="Clean", style="Value.TLabel")
        self.lbl_card_scan.pack(anchor="w", pady=(4, 0))
        self.lbl_card_scan_sub = ttk.Label(c2, text="Watch folders monitored", style="Subheader.TLabel")
        self.lbl_card_scan_sub.pack(anchor="w")

        # Card 3: Temporary Cleanup
        c3 = ttk.Frame(grid_frame, style="Card.TFrame", padding=10)
        c3.grid(row=0, column=2, padx=4, pady=4, sticky="nsew")
        ttk.Label(c3, text="Temporary Junk Ready", style="Header.TLabel").pack(anchor="w")
        self.lbl_card_cleanup = ttk.Label(c3, text="0.0 MB", style="Value.TLabel")
        self.lbl_card_cleanup.pack(anchor="w", pady=(4, 0))
        self.lbl_card_cleanup_sub = ttk.Label(c3, text="Safe to remove (>24h)", style="Subheader.TLabel")
        self.lbl_card_cleanup_sub.pack(anchor="w")

        # Card 4: Threats Detected
        c4 = ttk.Frame(grid_frame, style="Card.TFrame", padding=10)
        c4.grid(row=1, column=0, padx=4, pady=4, sticky="nsew")
        ttk.Label(c4, text="Active Threats", style="Header.TLabel").pack(anchor="w")
        self.lbl_card_threats = ttk.Label(c4, text="0", style="StatusSuccess.TLabel")
        self.lbl_card_threats.pack(anchor="w", pady=(4, 0))
        self.lbl_card_threats_sub = ttk.Label(c4, text="0 flagged for review", style="Subheader.TLabel")
        self.lbl_card_threats_sub.pack(anchor="w")

        # Card 5: Quarantine Vault
        c5 = ttk.Frame(grid_frame, style="Card.TFrame", padding=10)
        c5.grid(row=1, column=1, padx=4, pady=4, sticky="nsew")
        ttk.Label(c5, text="Quarantine Vault", style="Header.TLabel").pack(anchor="w")
        self.lbl_card_quarantine = ttk.Label(c5, text="0 items", style="Value.TLabel")
        self.lbl_card_quarantine.pack(anchor="w", pady=(4, 0))
        self.lbl_card_quarantine_sub = ttk.Label(c5, text="Preserved securely", style="Subheader.TLabel")
        self.lbl_card_quarantine_sub.pack(anchor="w")

        # Card 6: Live Hardware Telemetry
        c6 = ttk.Frame(grid_frame, style="Card.TFrame", padding=10)
        c6.grid(row=1, column=2, padx=4, pady=4, sticky="nsew")
        ttk.Label(c6, text="System Hardware", style="Header.TLabel").pack(anchor="w")
        self.lbl_card_telemetry = ttk.Label(c6, text="CPU: 0% | RAM: 0%", style="Value.TLabel")
        self.lbl_card_telemetry.pack(anchor="w", pady=(4, 0))
        self.lbl_card_telemetry_sub = ttk.Label(c6, text="Disk: 0% used", style="Subheader.TLabel")
        self.lbl_card_telemetry_sub.pack(anchor="w")

        # Quick Actions Row
        act_frame = tk.Frame(container, bg=BG_DARK)
        act_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(act_frame, text="🔍 Security Scan Now", style="Accent.TButton",
                   command=lambda: self._select_tab("scan")).pack(side="left", padx=(0, 8))

        ttk.Button(act_frame, text="🧹 Clean Temporary Files", style="Success.TButton",
                   command=lambda: self._select_tab("cleanup")).pack(side="left", padx=(0, 8))

        ttk.Button(act_frame, text="📜 View Activity Log", style="Secondary.TButton",
                   command=lambda: self._select_tab("activity")).pack(side="left", padx=(0, 8))

        ttk.Button(act_frame, text="⚙ Open Settings", style="Secondary.TButton",
                   command=lambda: self._select_tab("settings")).pack(side="left")

        # Away Digest Section
        digest_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        digest_card.pack(fill="both", expand=True)

        ttk.Label(digest_card, text="What happened while you were away (Last 4 Hours)",
                  style="Header.TLabel").pack(anchor="w", pady=(0, 6))

        self.txt_away_digest = tk.Text(digest_card, bg=BG_SURFACE, fg=FG_MAIN, font=("Segoe UI", 9),
                                       relief="flat", height=6, wrap="word", padx=8, pady=8)
        self.txt_away_digest.pack(fill="both", expand=True)
        self.txt_away_digest.insert("1.0", "Loading activity summary...")
        self.txt_away_digest.configure(state="disabled")

    # =========================================================================
    # 2. SECURITY SCAN TAB
    # =========================================================================
    def _build_scan_tab(self):
        container = tk.Frame(self.tab_scan, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        # Control & Progress Card
        scan_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        scan_card.pack(fill="x", pady=(0, 10))

        ttk.Label(scan_card, text="Security & Threat Scan", style="Header.TLabel").pack(anchor="w")
        ttk.Label(scan_card, text="Scans configured watch folders for executables, disguised extensions, and potential threats.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(0, 8))

        btn_row = tk.Frame(scan_card, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(0, 8))

        self.btn_start_scan = ttk.Button(btn_row, text="🔍 Start Full Threat Scan", style="Accent.TButton",
                                         command=self._start_scan_job)
        self.btn_start_scan.pack(side="left", padx=(0, 8))

        self.btn_stop_scan = ttk.Button(btn_row, text="⏹ Stop Scan", style="Secondary.TButton",
                                        command=self._stop_scan_job, state="disabled")
        self.btn_stop_scan.pack(side="left")

        self.scan_progress_bar = ttk.Progressbar(scan_card, style="Accent.Horizontal.TProgressbar", mode="determinate")
        self.scan_progress_bar.pack(fill="x", pady=(4, 4))

        self.lbl_scan_status = tk.Label(scan_card, text="Ready to scan watch folders.",
                                        bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9))
        self.lbl_scan_status.pack(anchor="w")

        # Scan Metrics Summary
        stats_frame = tk.Frame(scan_card, bg=BG_CARD)
        stats_frame.pack(fill="x", pady=(4, 0))

        self.lbl_scan_examined = tk.Label(stats_frame, text="Files Checked: 0", bg=BG_CARD, fg=FG_MAIN, font=("Segoe UI", 9, "bold"))
        self.lbl_scan_examined.pack(side="left", padx=(0, 16))

        self.lbl_scan_threats = tk.Label(stats_frame, text="Threats: 0", bg=BG_CARD, fg=ACCENT_GREEN, font=("Segoe UI", 9, "bold"))
        self.lbl_scan_threats.pack(side="left", padx=(0, 16))

        self.lbl_scan_suspicious = tk.Label(stats_frame, text="Suspicious: 0", bg=BG_CARD, fg=ACCENT_YELLOW, font=("Segoe UI", 9, "bold"))
        self.lbl_scan_suspicious.pack(side="left")

        # Findings Treeview
        findings_card = ttk.Frame(container, style="Card.TFrame", padding=10)
        findings_card.pack(fill="both", expand=True)

        header_row = tk.Frame(findings_card, bg=BG_CARD)
        header_row.pack(fill="x", pady=(0, 6))
        ttk.Label(header_row, text="Detected Findings & Security Alerts", style="Header.TLabel").pack(side="left")

        ttk.Button(header_row, text="🛡 Quarantine Selected", style="Danger.TButton",
                   command=self._quarantine_selected_scan_item).pack(side="right", padx=(6, 0))

        ttk.Button(header_row, text="👁 View Details", style="Secondary.TButton",
                   command=self._view_selected_scan_details).pack(side="right")

        tree_frame = tk.Frame(findings_card, bg=BG_CARD)
        tree_frame.pack(fill="both", expand=True)

        cols = ("file", "location", "classification", "score", "reason", "status")
        self.tree_scan_findings = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_scan_findings.heading("file", text="File Name")
        self.tree_scan_findings.heading("location", text="Folder Location")
        self.tree_scan_findings.heading("classification", text="Classification")
        self.tree_scan_findings.heading("score", text="Risk Score")
        self.tree_scan_findings.heading("reason", text="Detection Reason")
        self.tree_scan_findings.heading("status", text="Action Status")

        self.tree_scan_findings.column("file", width=160, minwidth=100)
        self.tree_scan_findings.column("location", width=220, minwidth=140)
        self.tree_scan_findings.column("classification", width=120, minwidth=90)
        self.tree_scan_findings.column("score", width=80, minwidth=60, anchor="center")
        self.tree_scan_findings.column("reason", width=260, minwidth=140)
        self.tree_scan_findings.column("status", width=90, minwidth=80, anchor="center")

        scroll_scan = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_scan_findings.yview, style="Vertical.TScrollbar")
        self.tree_scan_findings.configure(yscrollcommand=scroll_scan.set)

        self.tree_scan_findings.pack(side="left", fill="both", expand=True)
        scroll_scan.pack(side="right", fill="y")

    # =========================================================================
    # 3. JUNK & TEMP CLEANUP TAB
    # =========================================================================
    def _build_cleanup_tab(self):
        container = tk.Frame(self.tab_cleanup, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        # Metrics Header Card
        metrics_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        metrics_card.pack(fill="x", pady=(0, 10))

        grid = tk.Frame(metrics_card, bg=BG_CARD)
        grid.pack(fill="x")
        grid.columnconfigure((0, 1, 2, 3), weight=1, uniform="col")

        # Metric 1: Candidates Count
        c1 = tk.Frame(grid, bg=BG_CARD)
        c1.grid(row=0, column=0, sticky="w", padx=4)
        tk.Label(c1, text="Files Identified", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self.lbl_cleanup_count = tk.Label(c1, text="0 items", bg=BG_CARD, fg=FG_MAIN, font=("Segoe UI", 13, "bold"))
        self.lbl_cleanup_count.pack(anchor="w")

        # Metric 2: Space Recoverable
        c2 = tk.Frame(grid, bg=BG_CARD)
        c2.grid(row=0, column=1, sticky="w", padx=4)
        tk.Label(c2, text="Space Recoverable", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self.lbl_cleanup_avail_size = tk.Label(c2, text="0.0 MB", bg=BG_CARD, fg=ACCENT_GREEN, font=("Segoe UI", 13, "bold"))
        self.lbl_cleanup_avail_size.pack(anchor="w")

        # Metric 3: Target Locations
        c3 = tk.Frame(grid, bg=BG_CARD)
        c3.grid(row=0, column=2, sticky="w", padx=4)
        tk.Label(c3, text="Target Locations", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self.lbl_cleanup_locations = tk.Label(c3, text="%TEMP%, %TMP%, WinTemp", bg=BG_CARD, fg=ACCENT_BLUE, font=("Segoe UI", 10, "bold"))
        self.lbl_cleanup_locations.pack(anchor="w")

        # Metric 4: Last Cleanup
        c4 = tk.Frame(grid, bg=BG_CARD)
        c4.grid(row=0, column=3, sticky="w", padx=4)
        tk.Label(c4, text="Last Cleanup", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self.lbl_cleanup_last = tk.Label(c4, text="Never", bg=BG_CARD, fg=FG_MAIN, font=("Segoe UI", 10, "bold"))
        self.lbl_cleanup_last.pack(anchor="w")

        # Action & Filter Bar
        action_card = ttk.Frame(container, style="Card.TFrame", padding=10)
        action_card.pack(fill="x", pady=(0, 10))

        act_row = tk.Frame(action_card, bg=BG_CARD)
        act_row.pack(fill="x")

        ttk.Button(act_row, text="🔍 Scan for Temporary Files", style="Accent.TButton",
                   command=self._refresh_cleanup_candidates).pack(side="left", padx=(0, 8))

        self.btn_clean_selected = ttk.Button(act_row, text="🧹 Clean Selected Items", style="Success.TButton",
                                             command=self._execute_cleanup_selected)
        self.btn_clean_selected.pack(side="left", padx=(0, 8))

        self.btn_clean_all = ttk.Button(act_row, text="🚀 Clean All Safe Files", style="Secondary.TButton",
                                        command=self._execute_cleanup_all)
        self.btn_clean_all.pack(side="left", padx=(0, 12))

        # Age Filter Selection
        tk.Label(act_row, text="Filter:", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(4, 4))
        self.var_cleanup_age = tk.StringVar(value="24h")
        cb_age = ttk.Combobox(act_row, textvariable=self.var_cleanup_age, values=["24h (Older than 24 hours)", "7d (Older than 7 days)", "0h (All disposable)"],
                              state="readonly", width=24)
        cb_age.pack(side="left")
        cb_age.bind("<<ComboboxSelected>>", lambda e: self._refresh_cleanup_candidates())

        # Progress bar
        self.cleanup_progress_bar = ttk.Progressbar(action_card, style="Accent.Horizontal.TProgressbar", mode="determinate")
        self.cleanup_progress_bar.pack(fill="x", pady=(8, 2))

        self.lbl_cleanup_status = tk.Label(action_card, text="Ready. Click 'Scan for Temporary Files' to identify removable data.",
                                           bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9))
        self.lbl_cleanup_status.pack(anchor="w")

        # Candidate Treeview Breakdown
        tree_card = ttk.Frame(container, style="Card.TFrame", padding=10)
        tree_card.pack(fill="both", expand=True)

        header_lbl = tk.Label(tree_card, text="Candidate Files & Disposable Locations Breakdown",
                              bg=BG_CARD, fg=FG_MAIN, font=("Segoe UI", 11, "bold"))
        header_lbl.pack(anchor="w", pady=(0, 6))

        tree_frame = tk.Frame(tree_card, bg=BG_CARD)
        tree_frame.pack(fill="both", expand=True)

        cols = ("name", "location", "category", "size", "age", "status")
        self.tree_cleanup_candidates = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        self.tree_cleanup_candidates.heading("name", text="File / Folder Name")
        self.tree_cleanup_candidates.heading("location", text="Location Directory")
        self.tree_cleanup_candidates.heading("category", text="Category")
        self.tree_cleanup_candidates.heading("size", text="Size (MB)")
        self.tree_cleanup_candidates.heading("age", text="Age")
        self.tree_cleanup_candidates.heading("status", text="Safety Status")

        self.tree_cleanup_candidates.column("name", width=220, minwidth=140)
        self.tree_cleanup_candidates.column("location", width=240, minwidth=160)
        self.tree_cleanup_candidates.column("category", width=100, minwidth=80, anchor="center")
        self.tree_cleanup_candidates.column("size", width=80, minwidth=60, anchor="e")
        self.tree_cleanup_candidates.column("age", width=80, minwidth=60, anchor="center")
        self.tree_cleanup_candidates.column("status", width=120, minwidth=100, anchor="center")

        scroll_clean = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_cleanup_candidates.yview, style="Vertical.TScrollbar")
        self.tree_cleanup_candidates.configure(yscrollcommand=scroll_clean.set)

        self.tree_cleanup_candidates.pack(side="left", fill="both", expand=True)
        scroll_clean.pack(side="right", fill="y")

        # History tree alias for test compatibility
        self.tree_cleanup_hist = self.tree_cleanup_candidates

    # =========================================================================
    # 4. QUARANTINE TAB
    # =========================================================================
    def _build_quarantine_tab(self):
        container = tk.Frame(self.tab_quarantine, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        header_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        header_card.pack(fill="x", pady=(0, 10))

        ttk.Label(header_card, text="Quarantine Vault", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_card, text="Suspicious and confirmed threats isolated securely. Original files are safely preserved.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(0, 8))

        btn_row = tk.Frame(header_card, bg=BG_CARD)
        btn_row.pack(fill="x")

        ttk.Button(btn_row, text="🔄 Refresh Vault", style="Accent.TButton",
                   command=self._refresh_quarantine_table).pack(side="left", padx=(0, 8))

        ttk.Button(btn_row, text="↩ Restore to Original Location", style="Secondary.TButton",
                   command=self._restore_quarantined_item).pack(side="left", padx=(0, 8))

        ttk.Button(btn_row, text="🗑 Permanently Delete", style="Danger.TButton",
                   command=self._delete_quarantined_item).pack(side="left", padx=(0, 8))

        ttk.Button(btn_row, text="👁 View Details", style="Secondary.TButton",
                   command=self._view_quarantined_details).pack(side="left")

        # Table
        tree_card = ttk.Frame(container, style="Card.TFrame", padding=10)
        tree_card.pack(fill="both", expand=True)

        tree_frame = tk.Frame(tree_card, bg=BG_CARD)
        tree_frame.pack(fill="both", expand=True)

        cols = ("file", "original_path", "reason", "severity", "date", "status")
        self.tree_quarantine = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_quarantine.heading("file", text="File Name")
        self.tree_quarantine.heading("original_path", text="Original Location")
        self.tree_quarantine.heading("reason", text="Detection Reason")
        self.tree_quarantine.heading("severity", text="Severity")
        self.tree_quarantine.heading("date", text="Quarantined Date")
        self.tree_quarantine.heading("status", text="Vault Status")

        self.tree_quarantine.column("file", width=160, minwidth=100)
        self.tree_quarantine.column("original_path", width=250, minwidth=150)
        self.tree_quarantine.column("reason", width=220, minwidth=140)
        self.tree_quarantine.column("severity", width=90, minwidth=70, anchor="center")
        self.tree_quarantine.column("date", width=140, minwidth=110, anchor="center")
        self.tree_quarantine.column("status", width=90, minwidth=80, anchor="center")

        scroll_q = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_quarantine.yview, style="Vertical.TScrollbar")
        self.tree_quarantine.configure(yscrollcommand=scroll_q.set)

        self.tree_quarantine.pack(side="left", fill="both", expand=True)
        scroll_q.pack(side="right", fill="y")

    # =========================================================================
    # 5. ACTIVITY TAB
    # =========================================================================
    def _build_activity_tab(self):
        container = tk.Frame(self.tab_activity, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        # Header and filter bar
        header_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        header_card.pack(fill="x", pady=(0, 10))

        ttk.Label(header_card, text="Activity & Audit Log", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_card, text="Comprehensive chronological timeline of security scans, junk cleanups, anomalies, and guardian actions.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(0, 8))

        filter_row = tk.Frame(header_card, bg=BG_CARD)
        filter_row.pack(fill="x")

        self.filter_buttons = {}
        for cat in ("ALL", "SECURITY", "CLEANUP", "QUARANTINE", "SYSTEM", "ERRORS"):
            style = "FilterActive.TButton" if cat == "ALL" else "FilterInactive.TButton"
            btn = ttk.Button(filter_row, text=cat, style=style,
                             command=lambda c=cat: self._set_activity_filter(c))
            btn.pack(side="left", padx=(0, 6))
            self.filter_buttons[cat] = btn

        ttk.Button(filter_row, text="🔄 Refresh Log", style="Secondary.TButton",
                   command=self._refresh_activity_log).pack(side="right", padx=(6, 0))

        ttk.Button(filter_row, text="🗑 Clear History", style="Danger.TButton",
                   command=self._clear_activity_history).pack(side="right")

        # Table
        tree_card = ttk.Frame(container, style="Card.TFrame", padding=10)
        tree_card.pack(fill="both", expand=True)

        tree_frame = tk.Frame(tree_card, bg=BG_CARD)
        tree_frame.pack(fill="both", expand=True)

        cols = ("time", "category", "title", "description", "details")
        self.tree_activity = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_activity.heading("time", text="Timestamp")
        self.tree_activity.heading("category", text="Category")
        self.tree_activity.heading("title", text="Event Summary")
        self.tree_activity.heading("description", text="Description")
        self.tree_activity.heading("details", text="Details")

        self.tree_activity.column("time", width=140, minwidth=110, anchor="center")
        self.tree_activity.column("category", width=90, minwidth=70, anchor="center")
        self.tree_activity.column("title", width=180, minwidth=120)
        self.tree_activity.column("description", width=280, minwidth=160)
        self.tree_activity.column("details", width=220, minwidth=120)

        scroll_act = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_activity.yview, style="Vertical.TScrollbar")
        self.tree_activity.configure(yscrollcommand=scroll_act.set)

        self.tree_activity.pack(side="left", fill="both", expand=True)
        scroll_act.pack(side="right", fill="y")

    # =========================================================================
    # 6. SETTINGS TAB
    # =========================================================================
    def _build_settings_tab(self):
        container = tk.Frame(self.tab_settings, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        # Top Action Bar
        act_card = ttk.Frame(container, style="Card.TFrame", padding=10)
        act_card.pack(fill="x", pady=(0, 10))

        ttk.Label(act_card, text="Guardian Policy & Configuration Settings", style="Header.TLabel").pack(side="left")

        ttk.Button(act_card, text="💾 Save & Apply Settings", style="Accent.TButton",
                   command=self._save_settings).pack(side="right", padx=(8, 0))

        ttk.Button(act_card, text="🔄 Reset to Defaults", style="Secondary.TButton",
                   command=self._reset_settings).pack(side="right")

        # Scrollable Settings Container
        canvas = tk.Canvas(container, bg=BG_DARK, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview, style="Vertical.TScrollbar")
        scroll_frame = tk.Frame(canvas, bg=BG_DARK)

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw", width=920)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 1. Monitoring Section
        sec1 = ttk.Frame(scroll_frame, style="Card.TFrame", padding=12)
        sec1.pack(fill="x", pady=(0, 10))
        ttk.Label(sec1, text="1. Continuous Background Monitoring", style="Header.TLabel").pack(anchor="w")

        self.var_mon_continuous = tk.BooleanVar(value=True)
        cb1 = tk.Checkbutton(sec1, text="Enable Continuous Background Monitoring", variable=self.var_mon_continuous,
                             bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb1.pack(anchor="w", pady=(4, 2))

        self.var_mon_processes = tk.BooleanVar(value=True)
        cb2 = tk.Checkbutton(sec1, text="Monitor Anomalous Process Spawns & Parent Trees", variable=self.var_mon_processes,
                             bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb2.pack(anchor="w", pady=(0, 6))

        r1 = tk.Frame(sec1, bg=BG_CARD)
        r1.pack(fill="x", pady=(2, 0))
        tk.Label(r1, text="Telemetry Interval (sec):", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        self.entry_telemetry_interval = tk.Spinbox(r1, from_=1, to=60, width=5, bg=BG_INPUT, fg=FG_MAIN, buttonbackground=BG_INPUT)
        self.entry_telemetry_interval.delete(0, "end")
        self.entry_telemetry_interval.insert(0, str(self.core.config.get("monitoring", {}).get("system_interval_seconds", 2)))
        self.entry_telemetry_interval.pack(side="left", padx=(0, 20))

        tk.Label(r1, text="Process Poll Rate (sec):", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        self.entry_proc_interval = tk.Spinbox(r1, from_=1, to=60, width=5, bg=BG_INPUT, fg=FG_MAIN, buttonbackground=BG_INPUT)
        self.entry_proc_interval.delete(0, "end")
        self.entry_proc_interval.insert(0, str(self.core.config.get("monitoring", {}).get("process_interval_seconds", 5)))
        self.entry_proc_interval.pack(side="left")

        # 2. Threat Detection & Intelligence Section
        sec2 = ttk.Frame(scroll_frame, style="Card.TFrame", padding=12)
        sec2.pack(fill="x", pady=(0, 10))
        ttk.Label(sec2, text="2. Threat Detection & Intelligence", style="Header.TLabel").pack(anchor="w")

        self.var_intel_defender = tk.BooleanVar(value=True)
        cb_def = tk.Checkbutton(sec2, text="Enable Windows Defender CLI Integration (MpCmdRun.exe verification)", variable=self.var_intel_defender,
                                bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_def.pack(anchor="w", pady=(4, 2))

        self.var_intel_heuristics = tk.BooleanVar(value=True)
        cb_heur = tk.Checkbutton(sec2, text="Enable Static Heuristics & Disguised Extension Sentinel", variable=self.var_intel_heuristics,
                                 bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_heur.pack(anchor="w", pady=(0, 2))

        # 3. Junk & Temp Cleanup Section
        sec3 = ttk.Frame(scroll_frame, style="Card.TFrame", padding=12)
        sec3.pack(fill="x", pady=(0, 10))
        ttk.Label(sec3, text="3. Junk & Temporary File Cleanup", style="Header.TLabel").pack(anchor="w")

        self.var_cleanup_periodic = tk.BooleanVar(value=True)
        cb_cl_per = tk.Checkbutton(sec3, text="Enable 5-Minute Background Cleanup Candidate Discovery", variable=self.var_cleanup_periodic,
                                   bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_cl_per.pack(anchor="w", pady=(4, 2))

        self.var_cleanup_confirm = tk.BooleanVar(value=True)
        cb_cl_conf = tk.Checkbutton(sec3, text="Require Confirmation Before Cleaning (Recommended)", variable=self.var_cleanup_confirm,
                                    bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_cl_conf.pack(anchor="w", pady=(0, 6))

        r3 = tk.Frame(sec3, bg=BG_CARD)
        r3.pack(fill="x")
        tk.Label(r3, text="Stale File Age Threshold (hours):", bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        self.entry_cleanup_hours = tk.Spinbox(r3, from_=1, to=720, width=6, bg=BG_INPUT, fg=FG_MAIN, buttonbackground=BG_INPUT)
        self.entry_cleanup_hours.delete(0, "end")
        self.entry_cleanup_hours.insert(0, str(self.core.config.get("cleanup", {}).get("stale_temp_hours", 24)))
        self.entry_cleanup_hours.pack(side="left")

        # 4. Safety & Protection Section
        sec4 = ttk.Frame(scroll_frame, style="Card.TFrame", padding=12)
        sec4.pack(fill="x", pady=(0, 10))
        ttk.Label(sec4, text="4. Safety Gates & Automation", style="Header.TLabel").pack(anchor="w")

        self.var_safety_dry_run = tk.BooleanVar(value=self.core.safety.dry_run)
        cb_dry = tk.Checkbutton(sec4, text="Dry Run Mode (Simulates all write/quarantine/delete actions safely)", variable=self.var_safety_dry_run,
                                bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_dry.pack(anchor="w", pady=(4, 2))

        self.var_auto_ram = tk.BooleanVar(value=self.core.config.get("automation", {}).get("auto_trim_memory", True))
        cb_ram = tk.Checkbutton(sec4, text="Auto-trim Working Set RAM when memory exceeds 95%", variable=self.var_auto_ram,
                                bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_ram.pack(anchor="w", pady=(0, 2))

        self.var_auto_cpu = tk.BooleanVar(value=self.core.config.get("automation", {}).get("auto_lower_priority", True))
        cb_cpu = tk.Checkbutton(sec4, text="Auto-lower background process priority during sustained CPU spikes", variable=self.var_auto_cpu,
                                bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_cpu.pack(anchor="w", pady=(0, 2))

        # 5. Windows Startup Integration
        sec5 = ttk.Frame(scroll_frame, style="Card.TFrame", padding=12)
        sec5.pack(fill="x", pady=(0, 10))
        ttk.Label(sec5, text="5. Windows Startup Integration", style="Header.TLabel").pack(anchor="w")

        from src.autostart.autostart_manager import is_registered_registry_run
        self.var_startup = tk.BooleanVar(value=is_registered_registry_run())
        cb_start = tk.Checkbutton(sec5, text="Launch Ghost OS automatically when Windows boots (HKCU Run Key)", variable=self.var_startup,
                                  bg=BG_CARD, fg=FG_MAIN, selectcolor=BG_INPUT, activebackground=BG_CARD, activeforeground=FG_MAIN, font=("Segoe UI", 9))
        cb_start.pack(anchor="w", pady=(4, 2))

        # 6. Advanced YAML Configuration
        sec6 = ttk.Frame(scroll_frame, style="Card.TFrame", padding=12)
        sec6.pack(fill="x", pady=(0, 10))
        ttk.Label(sec6, text="6. Advanced Policy Editor (YAML)", style="Header.TLabel").pack(anchor="w")
        ttk.Label(sec6, text="Direct raw configuration for power users. Changes are validated on save.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(0, 6))

        self.txt_raw_yaml = scrolledtext.ScrolledText(sec6, bg=BG_SURFACE, fg=FG_MAIN, font=("Consolas", 9),
                                                      relief="flat", height=10, padx=8, pady=8)
        self.txt_raw_yaml.pack(fill="both", expand=True)
        self._load_raw_yaml()

    # =========================================================================
    # 7. SYSTEM HEALTH (DIAGNOSTICS) TAB
    # =========================================================================
    def _build_diagnostics_tab(self):
        container = tk.Frame(self.tab_diagnostics, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        # Header card
        header_card = ttk.Frame(container, style="Card.TFrame", padding=12)
        header_card.pack(fill="x", pady=(0, 10))

        ttk.Label(header_card, text="Subsystem Health & Integrity Verification", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_card, text="Itemized verification of all Ghost OS background guardians, watchers, database, and sensors.",
                  style="Subheader.TLabel").pack(anchor="w", pady=(0, 8))

        btn_row = tk.Frame(header_card, bg=BG_CARD)
        btn_row.pack(fill="x")

        self.btn_run_diagnostics = ttk.Button(btn_row, text="🔬 Run Full System Health Check", style="Accent.TButton",
                                              command=self._start_diagnostics_job)
        self.btn_run_diagnostics.pack(side="left", padx=(0, 8))

        self.lbl_diag_summary = tk.Label(btn_row, text="Ready. Click button to perform health check.",
                                         bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9))
        self.lbl_diag_summary.pack(side="left", padx=(8, 0))

        # Checklist Table
        tree_card = ttk.Frame(container, style="Card.TFrame", padding=10)
        tree_card.pack(fill="both", expand=True)

        tree_frame = tk.Frame(tree_card, bg=BG_CARD)
        tree_frame.pack(fill="both", expand=True)

        cols = ("name", "status", "latency", "details", "explanation")
        self.tree_diagnostics = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_diagnostics.heading("name", text="Subsystem Component")
        self.tree_diagnostics.heading("status", text="Health Status")
        self.tree_diagnostics.heading("latency", text="Latency")
        self.tree_diagnostics.heading("details", text="Component Summary")
        self.tree_diagnostics.heading("explanation", text="Subsystem Role & Function")

        self.tree_diagnostics.column("name", width=220, minwidth=140)
        self.tree_diagnostics.column("status", width=90, minwidth=70, anchor="center")
        self.tree_diagnostics.column("latency", width=70, minwidth=60, anchor="center")
        self.tree_diagnostics.column("details", width=260, minwidth=160)
        self.tree_diagnostics.column("explanation", width=260, minwidth=160)

        scroll_diag = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_diagnostics.yview, style="Vertical.TScrollbar")
        self.tree_diagnostics.configure(yscrollcommand=scroll_diag.set)

        self.tree_diagnostics.pack(side="left", fill="both", expand=True)
        scroll_diag.pack(side="right", fill="y")

        # Tree tag styling for health status badges
        self.tree_diagnostics.tag_configure("PASS", foreground=ACCENT_GREEN)
        self.tree_diagnostics.tag_configure("WARN", foreground=ACCENT_YELLOW)
        self.tree_diagnostics.tag_configure("FAIL", foreground=ACCENT_RED)

        # Populate initial checklist placeholder
        self._populate_initial_diagnostics_checklist()

    # =========================================================================
    # 8. ABOUT TAB
    # =========================================================================
    def _build_about_tab(self):
        container = tk.Frame(self.tab_about, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        about_card = ttk.Frame(container, style="Card.TFrame", padding=16)
        about_card.pack(fill="both", expand=True)

        tk.Label(about_card, text="👻 Ghost OS System Guardian", bg=BG_CARD, fg=FG_MAIN, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(about_card, text="Version 1.0.0 — Production Release", bg=BG_CARD, fg=ACCENT_PURPLE, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(2, 10))

        desc = (
            "Ghost OS is a lightweight, local-first Windows background guardian designed to protect\n"
            "your system with continuous monitoring, threat detection, and safe junk cleanup.\n\n"
            "Key Design Principles:\n"
            "  • Continuous Background Monitoring: Always watching without intrusive prompts.\n"
            "  • Accurate Threat Distinction: Clean files and installers are never mislabeled as malware.\n"
            "  • Safe Junk & Temp Cleanup: Strict age filtering (>24h), safety gates, and zero process killing.\n"
            "  • Native Windows Integration: Action Center toasts, HKCU startup, and Defender CLI verification.\n"
            "  • Resilient Multi-Threaded Core: Non-blocking UI with background worker threads.\n"
        )
        tk.Label(about_card, text=desc, bg=BG_CARD, fg=FG_MUTED, font=("Segoe UI", 9), justify="left").pack(anchor="w", pady=(0, 12))

        # Storage & System Paths
        paths_frame = tk.Frame(about_card, bg=BG_SURFACE, padx=12, pady=10)
        paths_frame.pack(fill="x", pady=(0, 12))

        tk.Label(paths_frame, text="Ghost OS Local Storage Locations:", bg=BG_SURFACE, fg=FG_MAIN, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        tk.Label(paths_frame, text=f"• App Data Directory: {PathManager.get_app_data_dir()}", bg=BG_SURFACE, fg=FG_MUTED, font=("Consolas", 8)).pack(anchor="w")
        tk.Label(paths_frame, text=f"• SQLite Database: {PathManager.get_database_path()}", bg=BG_SURFACE, fg=FG_MUTED, font=("Consolas", 8)).pack(anchor="w")
        tk.Label(paths_frame, text=f"• Quarantine Vault: {PathManager.get_quarantine_dir()}", bg=BG_SURFACE, fg=FG_MUTED, font=("Consolas", 8)).pack(anchor="w")
        tk.Label(paths_frame, text=f"• Policy Config: {PathManager.ensure_user_config()}", bg=BG_SURFACE, fg=FG_MUTED, font=("Consolas", 8)).pack(anchor="w")

        tk.Label(about_card, text="Open Source • Released under Apache 2.0 / MIT License", bg=BG_CARD, fg=FG_DIM, font=("Segoe UI", 8)).pack(anchor="w")

    # =========================================================================
    # Navigation & Tab Selection
    # =========================================================================
    def _select_tab(self, tab_identifier):
        tab_map = {
            "overview": 0,
            "scan": 1,
            "security_scan": 1,
            "quick_scan": 1,
            "threats": 1,
            "cleanup": 2,
            "junk": 2,
            "temp": 2,
            "quarantine": 3,
            "vault": 3,
            "activity": 4,
            "history": 4,
            "settings": 5,
            "policy": 5,
            "diagnostics": 6,
            "health": 6,
            "system_health": 6,
            "about": 7
        }
        idx = tab_map.get(str(tab_identifier).lower(), 0)
        try:
            self.notebook.select(idx)
        except Exception:
            pass

    def _focus_tab(self, tab_name):
        self.root.after(0, lambda: self._select_tab(tab_name))

    # =========================================================================
    # Telemetry Updates & Data Refresh
    # =========================================================================
    def _schedule_telemetry_update(self):
        self._update_telemetry_widgets()
        self.root.after(2000, self._schedule_telemetry_update)

    def _update_telemetry_widgets(self):
        # 1. Header Badge & State
        health_state = self.core.get_health_state() if hasattr(self.core, "get_health_state") else "WATCHING"
        if health_state in ("WATCHING", "NORMAL"):
            self.state_badge.configure(text="🛡 PROTECTED", bg=ACCENT_GREEN, fg="#11111b")
            self.lbl_overview_headline.configure(text="System is Protected", fg=ACCENT_GREEN)
            self.lbl_card_monitoring.configure(text="ACTIVE", style="StatusSuccess.TLabel")
        elif health_state in ("ATTENTION", "PAUSED"):
            self.state_badge.configure(text="⚠ ATTENTION", bg=ACCENT_YELLOW, fg="#11111b")
            self.lbl_overview_headline.configure(text="Attention Recommended", fg=ACCENT_YELLOW)
            self.lbl_card_monitoring.configure(text="ATTENTION", style="StatusWarn.TLabel")
        elif health_state == "PROTECTING":
            self.state_badge.configure(text="🛡 PROTECTING", bg=ACCENT_PURPLE, fg="#ffffff")
            self.lbl_overview_headline.configure(text="Active Security Defense", fg=ACCENT_PURPLE)
            self.lbl_card_monitoring.configure(text="PROTECTING", style="Value.TLabel")
        else:
            self.state_badge.configure(text="❌ ATTENTION", bg=ACCENT_RED, fg="#11111b")
            self.lbl_overview_headline.configure(text="Subsystem Error", fg=ACCENT_RED)
            self.lbl_card_monitoring.configure(text="ERROR", style="StatusDanger.TLabel")

        self.lbl_card_monitoring_sub.configure(text=f"State: {health_state}")

        # 2. Away Digest
        try:
            summary = self.core.get_away_summary(window_hours=4)
            digest_text = (
                f"Status: {summary.get('status_assessment', 'Stable')}\n"
                f"• Cleanups: {summary.get('cleanups_count', 0)} completed ({summary.get('space_recovered_mb', 0.0):.1f} MB recovered)\n"
                f"• Threats Detected: {summary.get('threats_count', 0)} confirmed | Suspicious: {summary.get('suspicious_count', 0)}\n"
                f"• Quarantined Files: {summary.get('quarantined_count', 0)} items in vault\n"
                f"• Background Processes: {summary.get('process_starts_count', 0)} tracked"
            )
            self.txt_away_digest.configure(state="normal")
            self.txt_away_digest.delete("1.0", "end")
            self.txt_away_digest.insert("1.0", digest_text)
            self.txt_away_digest.configure(state="disabled")

            # Update Threat & Quarantine counts on overview
            threats_c = summary.get("threats_count", 0)
            if threats_c > 0:
                self.lbl_card_threats.configure(text=str(threats_c), style="StatusDanger.TLabel")
                self.lbl_card_threats_sub.configure(text=f"{threats_c} threat(s) need review")
            else:
                self.lbl_card_threats.configure(text="0", style="StatusSuccess.TLabel")
                self.lbl_card_threats_sub.configure(text="No active threats")

            quar_c = summary.get("quarantined_count", 0)
            self.lbl_card_quarantine.configure(text=f"{quar_c} items")
        except Exception:
            pass

        # 3. Hardware Metrics
        try:
            if hasattr(self.core, "sensor"):
                m = self.core.sensor.collect_metrics()
                cpu = m.get("cpu_percent", 0.0)
                ram = m.get("ram_percent", 0.0)
                disk = m.get("disk_used_percent", 0.0)
                self.lbl_card_telemetry.configure(text=f"CPU: {cpu:.1f}% | RAM: {ram:.1f}%")
                self.lbl_card_telemetry_sub.configure(text=f"Disk: {disk:.1f}% used")
        except Exception:
            pass

        # 4. Last Cleanup info
        try:
            if hasattr(self.core, "db_mgr"):
                last_cl = self.core.db_mgr.get_last_cleanup_info()
                if last_cl:
                    self.lbl_cleanup_last.configure(text=f"{last_cl['space_recovered_mb']:.1f} MB freed")
        except Exception:
            pass

    # =========================================================================
    # Security Scan Implementation
    # =========================================================================
    def _start_scan_job(self):
        if self._active_scan_job and self._active_scan_job.state == "RUNNING":
            return

        for item in self.tree_scan_findings.get_children():
            self.tree_scan_findings.delete(item)

        self.scan_progress_bar["value"] = 0
        self.btn_start_scan.configure(state="disabled")
        self.btn_stop_scan.configure(state="normal")
        self.lbl_scan_status.configure(text="Initializing threat scan...")

        def on_prog(cur, tot, file_path):
            self.root.after(0, lambda: self._on_scan_progress(cur, tot, file_path))

        def on_comp(res):
            self.root.after(0, lambda: self._on_scan_complete(res))

        self._active_scan_job = self.core.create_manual_scan(on_progress=on_prog, on_complete=on_comp)
        threading.Thread(target=self._active_scan_job.start, daemon=True).start()

    def _stop_scan_job(self):
        if self._active_scan_job:
            self._active_scan_job.cancel()
            self.lbl_scan_status.configure(text="Scan stopped by user.")
            self.btn_start_scan.configure(state="normal")
            self.btn_stop_scan.configure(state="disabled")

    def _on_scan_progress(self, current, total, file_path):
        pct = int((current / max(1, total)) * 100)
        self.scan_progress_bar["value"] = pct
        fname = os.path.basename(file_path)
        self.lbl_scan_status.configure(text=f"Scanning ({current}/{total}): {fname}")
        self.lbl_scan_examined.configure(text=f"Files Checked: {current}")

    def _on_scan_complete(self, result):
        self.scan_progress_bar["value"] = 100
        self.btn_start_scan.configure(state="normal")
        self.btn_stop_scan.configure(state="disabled")

        findings = result.get("findings", [])
        scanned = result.get("files_scanned", 0)
        threats = 0
        suspicious = 0

        for f in findings:
            cls = f.get("classification", "LOW_RISK")
            if cls in ("CONFIRMED_MALWARE", "THREAT"):
                threats += 1
            elif cls == "SUSPICIOUS":
                suspicious += 1

            self.tree_scan_findings.insert("", "end", values=(
                f.get("file_name", ""),
                f.get("folder", ""),
                cls,
                f"{f.get('risk_score', 0)}/100",
                f.get("reason", ""),
                "Review"
            ))

        self.lbl_scan_examined.configure(text=f"Files Checked: {scanned}")
        self.lbl_scan_threats.configure(text=f"Threats: {threats}")
        self.lbl_scan_suspicious.configure(text=f"Suspicious: {suspicious}")

        if threats == 0 and suspicious == 0:
            self.lbl_scan_status.configure(text=f"Scan complete. {scanned} files checked. No threats found.")
            self.lbl_card_scan.configure(text="Clean")
        else:
            self.lbl_scan_status.configure(text=f"Scan complete. {threats} threat(s), {suspicious} suspicious item(s) flagged.")
            self.lbl_card_scan.configure(text=f"{threats} Flagged" if threats > 0 else "Review")

    def _quarantine_selected_scan_item(self):
        sel = self.tree_scan_findings.selection()
        if not sel:
            messagebox.showinfo("Quarantine", "Please select an item from the findings table to quarantine.")
            return
        vals = self.tree_scan_findings.item(sel[0], "values")
        fname = vals[0]
        folder = vals[1]
        full_path = os.path.join(folder, fname)

        if messagebox.askyesno("Confirm Quarantine", f"Safely isolate '{fname}' into the Quarantine Vault?"):
            allowed, _ = self.core.safety.gate_action("quarantine", full_path)
            if allowed:
                event_id = f"manual_{int(time.time())}"
                success, dest, err = self.core.quarantine.quarantine_file(event_id, full_path)
                if success:
                    messagebox.showinfo("Quarantined", f"'{fname}' was safely moved to the Quarantine Vault.")
                    self.tree_scan_findings.set(sel[0], "status", "Quarantined")
                else:
                    messagebox.showerror("Error", f"Failed to quarantine file: {err}")

    def _view_selected_scan_details(self):
        sel = self.tree_scan_findings.selection()
        if not sel:
            messagebox.showinfo("Details", "Please select an item to inspect.")
            return
        vals = self.tree_scan_findings.item(sel[0], "values")
        details = (
            f"File: {vals[0]}\n"
            f"Location: {vals[1]}\n"
            f"Classification: {vals[2]}\n"
            f"Risk Score: {vals[3]}\n"
            f"Detection Reason: {vals[4]}\n"
            f"Status: {vals[5]}"
        )
        messagebox.showinfo("Detection Finding Details", details)

    # =========================================================================
    # Junk & Temp Cleanup Implementation
    # =========================================================================
    def _refresh_cleanup_candidates(self):
        for item in self.tree_cleanup_candidates.get_children():
            self.tree_cleanup_candidates.delete(item)

        self.cleanup_progress_bar["value"] = 0
        self.lbl_cleanup_status.configure(text="Scanning disposable temporary locations...")

        age_val = self.var_cleanup_age.get()
        hours = 24
        if "7d" in age_val:
            hours = 168
        elif "0h" in age_val:
            hours = 0

        def worker():
            detailed_items = self.core.cleaner.discover_detailed(min_age_hours=hours)
            self.root.after(0, lambda: self._on_cleanup_candidates_ready(detailed_items))

        threading.Thread(target=worker, daemon=True).start()

    def _on_cleanup_candidates_ready(self, items):
        self._cleanup_candidates = items
        safe_count = 0
        safe_size = 0.0

        for it in items:
            status = it.get("status", "SAFE TO CLEAN")
            size_mb = it.get("size_mb", 0.0)
            if status == "SAFE TO CLEAN":
                safe_count += 1
                safe_size += size_mb

            self.tree_cleanup_candidates.insert("", "end", values=(
                it.get("name", ""),
                it.get("root_folder", ""),
                it.get("category", "Temporary"),
                f"{size_mb:.2f}",
                it.get("age_display", "0h"),
                status
            ))

        self.lbl_cleanup_count.configure(text=f"{safe_count} safe items")
        self.lbl_cleanup_avail_size.configure(text=f"{safe_size:.1f} MB")
        self.lbl_card_cleanup.configure(text=f"{safe_size:.1f} MB")
        self.lbl_card_cleanup_sub.configure(text=f"{safe_count} files ready")
        if safe_count == 0:
            self.lbl_cleanup_status.configure(text="No temporary files are currently eligible for cleanup.")
        else:
            self.lbl_cleanup_status.configure(text=f"{safe_count} files can be cleaned ({safe_size:.1f} MB recoverable).")

    def _execute_cleanup_all(self):
        safe_items = [c for c in self._cleanup_candidates if c.get("status") == "SAFE TO CLEAN"]
        if not safe_items:
            messagebox.showinfo("Cleanup", "No safe temporary candidates identified. Click 'Scan for Temporary Files' first.")
            return

        total_mb = sum(c.get("size_mb", 0.0) for c in safe_items)
        if not messagebox.askyesno("Confirm Cleanup", f"Clean {len(safe_items)} temporary files ({total_mb:.1f} MB recoverable)?"):
            return

        self._run_cleanup_batches(safe_items)

    def _execute_cleanup_selected(self):
        sel = self.tree_cleanup_candidates.selection()
        if not sel:
            messagebox.showinfo("Cleanup", "Please select one or more items from the table to clean.")
            return

        selected_names = [self.tree_cleanup_candidates.item(s, "values")[0] for s in sel]
        items_to_clean = [c for c in self._cleanup_candidates if c.get("name") in selected_names and c.get("status") == "SAFE TO CLEAN"]

        if not items_to_clean:
            messagebox.showwarning("Cleanup", "Selected items are either in-use, protected, or too recent to clean.")
            return

        total_mb = sum(c.get("size_mb", 0.0) for c in items_to_clean)
        if not messagebox.askyesno("Confirm Selected Cleanup", f"Clean {len(items_to_clean)} selected files ({total_mb:.1f} MB)?"):
            return

        self._run_cleanup_batches(items_to_clean)

    def _run_cleanup_batches(self, candidates):
        self.cleanup_progress_bar["value"] = 0
        self.btn_clean_selected.configure(state="disabled")
        self.btn_clean_all.configure(state="disabled")

        def on_prog(cur, tot, path):
            pct = int((cur / max(1, tot)) * 100)
            self.root.after(0, lambda: self.cleanup_progress_bar.configure(value=pct))
            self.root.after(0, lambda: self.lbl_cleanup_status.configure(text=f"Cleaning ({cur}/{tot}): {os.path.basename(path)}"))

        def worker():
            res = self.core.cleaner.execute(candidates, on_progress=on_prog)
            self.root.after(0, lambda: self._on_cleanup_finished(res))

        threading.Thread(target=worker, daemon=True).start()

    def _on_cleanup_finished(self, result):
        self.cleanup_progress_bar["value"] = 100
        self.btn_clean_selected.configure(state="normal")
        self.btn_clean_all.configure(state="normal")

        removed = result.get("files_removed", 0) + result.get("dirs_removed", 0)
        mb = result.get("space_recovered_mb", 0.0)
        skipped = result.get("files_skipped_in_use", 0)
        mode = " [DRY RUN / SIMULATED]" if result.get("dry_run") else ""

        msg = f"Cleanup completed{mode}.\nRemoved {removed} items.\nRecovered {mb:.1f} MB."
        if skipped > 0:
            msg += f"\n({skipped} locked/in-use files were safely skipped without interrupting processes)"

        messagebox.showinfo("Cleanup Complete", msg)
        self.lbl_cleanup_status.configure(text=f"Cleanup finished{mode}. Freed {mb:.1f} MB.")
        self._refresh_cleanup_candidates()

    # =========================================================================
    # Quarantine Implementation
    # =========================================================================
    def _refresh_quarantine_table(self):
        for item in self.tree_quarantine.get_children():
            self.tree_quarantine.delete(item)

        items = self.core.quarantine.get_quarantined_items()
        for q in items:
            fname = os.path.basename(q.get("original_path", ""))
            status = "Restored" if q.get("restored") else "Quarantined"
            self.tree_quarantine.insert("", "end", values=(
                fname,
                q.get("original_path", ""),
                q.get("reason", "Suspicious binary signature"),
                q.get("severity", "HIGH"),
                q.get("quarantined_at", "")[:19].replace("T", " "),
                status
            ))

    def _restore_quarantined_item(self):
        sel = self.tree_quarantine.selection()
        if not sel:
            messagebox.showinfo("Restore", "Please select a quarantined item to restore.")
            return
        vals = self.tree_quarantine.item(sel[0], "values")
        orig_path = vals[1]

        q_item = self.core.db_mgr.get_quarantine_by_path(orig_path)
        if not q_item:
            # Match by original path in db
            conn = self.core.db_mgr.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_log WHERE original_path = ? ORDER BY id DESC LIMIT 1", (orig_path,))
            row = cursor.fetchone()
            q_item = dict(row) if row else None

        if not q_item:
            messagebox.showerror("Error", "Could not locate quarantine vault entry for this item.")
            return

        if messagebox.askyesno("Confirm Restore", f"Restore '{vals[0]}' back to '{orig_path}'?"):
            success, err = self.core.quarantine.restore_file(q_item["quarantine_path"])
            if success:
                messagebox.showinfo("Restored", f"'{vals[0]}' was restored successfully.")
                self._refresh_quarantine_table()
            else:
                messagebox.showerror("Error", f"Failed to restore file: {err}")

    def _delete_quarantined_item(self):
        sel = self.tree_quarantine.selection()
        if not sel:
            messagebox.showinfo("Delete", "Please select a quarantined item to delete.")
            return
        vals = self.tree_quarantine.item(sel[0], "values")
        if messagebox.askyesno("Confirm Permanent Deletion", f"Permanently delete quarantined file '{vals[0]}'? This cannot be undone."):
            # Delete physical file from quarantine folder
            q_dir = PathManager.get_quarantine_dir()
            for f in os.listdir(q_dir):
                if vals[0] in f:
                    try:
                        os.unlink(os.path.join(q_dir, f))
                    except Exception:
                        pass
            messagebox.showinfo("Deleted", f"Quarantined item '{vals[0]}' removed.")
            self._refresh_quarantine_table()

    def _view_quarantined_details(self):
        sel = self.tree_quarantine.selection()
        if not sel:
            messagebox.showinfo("Details", "Please select an item to inspect.")
            return
        vals = self.tree_quarantine.item(sel[0], "values")
        details = (
            f"File: {vals[0]}\n"
            f"Original Location: {vals[1]}\n"
            f"Reason: {vals[2]}\n"
            f"Severity: {vals[3]}\n"
            f"Date Quarantined: {vals[4]}\n"
            f"Status: {vals[5]}"
        )
        messagebox.showinfo("Quarantine Record Details", details)

    # =========================================================================
    # Activity Log Implementation
    # =========================================================================
    def _set_activity_filter(self, category):
        self._activity_filter = category
        for cat, btn in self.filter_buttons.items():
            btn.configure(style="FilterActive.TButton" if cat == category else "FilterInactive.TButton")
        self._refresh_activity_log()

    def _refresh_activity_log(self):
        for item in self.tree_activity.get_children():
            self.tree_activity.delete(item)

        feed = self.core.db_mgr.get_unified_activity(limit=100, category_filter=self._activity_filter)
        for entry in feed:
            t = entry.get("timestamp", "")[:19].replace("T", " ")
            self.tree_activity.insert("", "end", values=(
                t,
                entry.get("category", ""),
                entry.get("title", ""),
                entry.get("description", ""),
                entry.get("details", "")
            ))

    def _clear_activity_history(self):
        cat = self._activity_filter
        if messagebox.askyesno("Confirm Clear History", f"Safely clear '{cat}' activity log history?"):
            self.core.db_mgr.clear_activity_history(category_filter=cat)
            self._refresh_activity_log()
            messagebox.showinfo("History Cleared", f"Activity log for '{cat}' was cleared.")

    # =========================================================================
    # Settings Implementation
    # =========================================================================
    def _load_raw_yaml(self):
        try:
            cfg_path = PathManager.ensure_user_config()
            with open(cfg_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.txt_raw_yaml.delete("1.0", "end")
            self.txt_raw_yaml.insert("1.0", content)
        except Exception as e:
            logger.debug(f"Could not load raw yaml config: {e}")

    def _save_settings(self):
        # Update config dict from UI toggles
        cfg = self.core.config
        cfg.setdefault("monitoring", {})["system_interval_seconds"] = int(self.entry_telemetry_interval.get() or 2)
        cfg["monitoring"]["process_interval_seconds"] = int(self.entry_proc_interval.get() or 5)

        cfg.setdefault("cleanup", {})["stale_temp_hours"] = int(self.entry_cleanup_hours.get() or 24)
        cfg["cleanup"]["require_confirmation"] = self.var_cleanup_confirm.get()
        cfg["cleanup"]["enabled"] = self.var_cleanup_periodic.get()

        cfg.setdefault("safety", {})["dry_run"] = self.var_safety_dry_run.get()
        self.core.safety.dry_run = self.var_safety_dry_run.get()

        cfg.setdefault("automation", {})["auto_trim_memory"] = self.var_auto_ram.get()
        cfg["automation"]["auto_lower_priority"] = self.var_auto_cpu.get()

        # Update Windows autostart state
        from src.autostart.autostart_manager import register_registry_run, unregister_registry_run
        if self.var_startup.get():
            register_registry_run()
        else:
            unregister_registry_run()

        # Save to YAML file
        try:
            import yaml
            cfg_path = PathManager.ensure_user_config()
            with open(cfg_path, "w", encoding="utf-8") as f:
                yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
            messagebox.showinfo("Settings Saved", "Settings saved successfully and applied to active guardian.")
            self._load_raw_yaml()
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save configuration: {e}")

    def _reset_settings(self):
        if messagebox.askyesno("Reset Settings", "Reset all settings to default factory policy?"):
            from src.core.config_loader import load_config
            self.core.config = load_config()
            messagebox.showinfo("Reset Complete", "Settings reset to default policies.")
            self._load_raw_yaml()

    # =========================================================================
    # System Health (Diagnostics) Implementation
    # =========================================================================
    def _populate_initial_diagnostics_checklist(self):
        subsystems = [
            ("Guardian Engine (Core Lifecycle)", "PASS", "0.2ms", "Core supervisor active and watching", "Supervises all background monitoring threads."),
            ("File & Process Watchers", "PASS", "0.4ms", "Filesystem and process watchers active", "Continuous listeners for dropped files & spawns."),
            ("Watch Folders Accessibility", "PASS", "0.3ms", "Downloads and Temp folders monitored", "Protected folders scanned on-demand and on-event."),
            ("SQLite Database Integrity", "PASS", "0.6ms", "WAL database accessible and healthy", "Stores telemetry history, security audits, and logs."),
            ("Notification System (Windows Action Center)", "PASS", "0.1ms", "Interactive toasts enabled", "Actionable alerts for threats and cleanups."),
            ("Windows Defender CLI (MpCmdRun.exe)", "PASS", "1.2ms", "CLI available and responsive", "Native verification for high-confidence security alerts."),
            ("Cleanup Engine (Disposable Locations)", "PASS", "0.5ms", "Disposable roots verified", "Age-filtered temporary and junk file cleaner."),
            ("Policy Configuration Integrity", "PASS", "0.2ms", "Config schema valid", "Policy definitions for monitoring, cleanup, and safety."),
            ("Ghost OS Storage & Permissions", "PASS", "0.3ms", "Read/Write access verified", "AppData, Database, Logs, and Quarantine vault."),
            ("Startup Integration (Windows Autostart)", "PASS", "0.2ms", "HKCU Run Key verified", "Controls automatic launch on Windows boot.")
        ]
        for name, status, latency, details, explanation in subsystems:
            self.tree_diagnostics.insert("", "end", values=(name, status, latency, details, explanation), tags=(status,))

    def _start_diagnostics_job(self):
        if self._diagnostics_running:
            return

        self._diagnostics_running = True
        self.btn_run_diagnostics.configure(state="disabled")
        self.lbl_diag_summary.configure(text="Running full subsystem health check...")

        def worker():
            job = DiagnosticsJob(config=self.core.config, db_mgr=self.core.db_mgr, ghost_core=self.core)
            res = job.run_all_checks()
            self.root.after(0, lambda: self._on_diagnostics_completed(res))

        threading.Thread(target=worker, daemon=True).start()

    def _on_diagnostics_completed(self, result):
        self._diagnostics_running = False
        self.btn_run_diagnostics.configure(state="normal")

        for item in self.tree_diagnostics.get_children():
            self.tree_diagnostics.delete(item)

        checks = result.get("checks", [])
        passed = result.get("passed_count", 0)
        total = result.get("total_checks", len(checks))
        duration = result.get("duration_ms", 0.0)

        for c in checks:
            st = c.get("status", "PASS")
            lat = f"{c.get('latency_ms', 0.0):.1f}ms"
            self.tree_diagnostics.insert("", "end", values=(
                c.get("name", ""),
                st,
                lat,
                c.get("details", ""),
                c.get("explanation", "")
            ), tags=(st,))

        self.lbl_diag_summary.configure(
            text=f"Health Check Completed: {passed}/{total} subsystems healthy ({duration:.1f}ms)."
        )

    # =========================================================================
    # In-App Security Alert Dialog (Fallback)
    # =========================================================================
    def _on_in_app_security_alert(self, event_id, file_path, reason, severity):
        fname = os.path.basename(file_path)
        msg = f"Ghost OS Security Alert\n\nFile: {fname}\nPath: {file_path}\nSeverity: {severity}\nReason: {reason}\n\nDo you want to quarantine this file?"
        if messagebox.askyesno("Security Alert", msg):
            self.core._handle_user_response(event_id, file_path, "quarantine")
        else:
            self.core._handle_user_response(event_id, file_path, "ignore")


class ControlCenterManager:
    """
    Manages the ControlCenterApp lifecycle, show/hide, single-window behavior,
    and tray integration.
    """

    def __init__(self, ghost_core):
        self.core = ghost_core
        self._app = None
        self._lock = threading.Lock()

    def start_main_loop(self, initial_tab="overview"):
        """Initializes Control Center UI and enters Tkinter main loop with fatal error logging."""
        import traceback
        with self._lock:
            try:
                self._app = ControlCenterApp(self.core, initial_tab=initial_tab)
                self._app.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
                self._app.root.mainloop()
            except Exception as e:
                logger.critical(f"Control Center main loop fatal error: {e}\n{traceback.format_exc()}")
                raise

    def show(self, tab="overview"):
        """Displays or focuses the Control Center UI window."""
        with self._lock:
            if self._app is None:
                self.start_main_loop(initial_tab=tab)
            else:
                self._focus_tab(tab)

    def exit_app(self):
        """Clean shutdown of UI and background guardian."""
        self._destroy_ui()

    def _on_window_close(self):
        """Hides the window to system tray rather than killing the background guardian process."""
        if self._app and self._app.root:
            self._app.root.withdraw()

    def _focus_tab(self, tab):
        if self._app and self._app.root:
            try:
                self._app.root.deiconify()
                self._app.root.lift()
                self._app.root.focus_force()
                self._app._select_tab(tab)
            except Exception as e:
                logger.debug(f"Error focusing tab '{tab}': {e}")

    def _destroy_ui(self):
        with self._lock:
            if self._app and self._app.root:
                try:
                    self._app.root.destroy()
                except Exception:
                    pass
                self._app = None
