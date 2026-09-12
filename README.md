# Ghost OS

**A lightweight Windows background guardian for threat detection, system monitoring, quarantine, and safe temporary-file cleanup.**

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078d4?style=flat-square)](https://microsoft.com/windows)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-108%20passing-brightgreen?style=flat-square)](https://pytest.org)
[![Architecture](https://img.shields.io/badge/architecture-local--first-9cf?style=flat-square)](https://github.com/bk5859200-blip/Ghost-OS)
[![License](https://img.shields.io/badge/license-unspecified-lightgrey?style=flat-square)](#license)

<p align="center">
  <img src="assets/control-center-overview.png" alt="Ghost OS Control Center" width="860">
</p>

<p align="center"><em>Ghost OS Control Center — real-time security status, eight management tabs, multi-signal threat visibility, quarantine vault, and system diagnostics.</em></p>

---

## Overview

Ghost OS is an open-source, local-first background security guardian and system maintenance application for Windows. It runs silently alongside your primary antivirus (such as Microsoft Defender), adding continuous behavioral observation, multi-signal threat detection, an isolated quarantine vault, and automated stale temporary-file cleanup, without disrupting everyday desktop use.

The system is built for explainability and local operation. Every risk assessment is mapped to observable signals — Authenticode digital signatures, publisher reputation, Microsoft Defender CLI scans, naming anomalies, and behavioral diffs. Monitoring, telemetry, and security operations execute entirely on the local machine, and destructive actions are gated behind explicit authorization and safety controls.

## Key Capabilities

| Capability | Description |
|---|---|
| Continuous background monitoring | Watches `Downloads`, `Desktop`, and `Temp`; monitors running processes; tracks live CPU, RAM. |
| Explainable threat detection | Combines local rule heuristics, Microsoft Defender (`MpCmdRun.exe`), and Authenticode verification to produce a 0–100 risk score. |
| Five-tier risk classification | Separates `CLEAN`, `LOW_RISK`, `SUSPICIOUS`, `THREAT`, and `CONFIRMED_MALWARE` so ordinary downloads are never mislabeled as malware. |
| Quarantine vault | Isolates suspicious files with SHA-256 hash verification and original-path restoration. |
| Windows temp and junk cleaner | Safely discovers and removes stale temporary files (older than 24 hours) without terminating active processes. |
| Windows notifications | Native Action Center toast alerts with actionable buttons (Quarantine, Leave it alone, View details). |
| Native control center | A responsive, dark-themed desktop interface with eight dedicated management tabs. |
| Safety engine | Protects Windows system directories and critical processes, and enforces a `dry_run` safety mode. |
| Local telemetry | Persistent SQLite audit log of detections, process lifecycles, and cleanup operations. |
| Production packaging | Standalone PyInstaller executable (`GhostOS.exe`) and an Inno Setup installer (`GhostOS-Setup.exe`). |

## Table of Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Core Subsystems](#core-subsystems)
- [Security Model](#security-model)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Developer Setup](#developer-setup)
- [Testing](#testing)
- [Building](#building)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Windows Startup](#windows-startup)
- [Privacy and Local-First Design](#privacy-and-local-first-design)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Responsible Use](#responsible-use)

---

## Core Subsystems

### 1. Continuous Guardian

Runs as a lightweight background service with minimal overhead (approximately 0.1% CPU at idle):

- **File system watcher** — monitors configured watch roots (`%USERPROFILE%\Downloads`, `%USERPROFILE%\Desktop`, `%TEMP%`) for file creation and modification, with event debouncing and a bounded worker thread pool.
- **Process watcher** — performs periodic process snapshot diffing to detect newly spawned processes and inspect parent/child relationships, without kernel-level hooks.
- **System telemetry** — samples CPU, RAM, disk, and I/O throughput every two seconds, recording smoothed metrics in SQLite.
- **Single-instance enforcement** — uses a Windows named mutex (`Global\GhostOS_SingleInstance_Mutex`) to guarantee only one guardian instance runs at a time.
- **Pause/resume lifecycle** — background watchers can be paused instantly from the tray icon or the Control Center.

### 2. Threat Detection Pipeline

Every file event or manual scan request passes through a multi-stage evaluation pipeline:

```text
       File / Process Event
                │
                ▼
        [ Threat Sentinel ]
                │
   ┌────────────┴────────────┐
   ▼                         ▼
[ Rule Engine ]      [ Defender Scanner ]
(Signatures & Names)  (MpCmdRun.exe CLI)
   │                         │
   └────────────┬────────────┘
                ▼
      [ Anomaly Detector ]
                │
                ▼
      [ Decision Engine ]
 (Maps Score & Category to 5-Tier Level)
                │
                ▼
       [ Safety Engine ]
 (Protected Paths & dry_run Policy)
                │
                ▼
  [ Action: LOG / NOTIFY / QUARANTINE ]
```

1. **Threat Sentinel** — coordinates analysis workers with bounded concurrency to prevent CPU starvation.
2. **Rule Engine** — analyzes Authenticode signatures, verified publisher metadata, disguised double extensions (e.g. `invoice.pdf.exe`), script execution in unusual folders, and entropy.
3. **Defender Scanner** — offloads real-time signature scanning to Microsoft Defender via `MpCmdRun.exe`, without spawning visible console windows.
4. **Decision Engine** — synthesizes rule scores and Defender outcomes into an explainable verdict.
5. **Safety Engine** — verifies target paths are not protected system roots before permitting quarantine or deletion.

### 3. Context-Aware Risk Classification

A strict five-tier hierarchy prevents alarm fatigue — a newly downloaded installer or unsigned utility is never labeled malware without definitive indicators.

| Classification | Criteria | Action | User Prompt |
|---|---|---|---|
| `CLEAN` | Score 0–19. Verified signature, benign location, clean Defender scan. | Logged silently | None |
| `LOW_RISK` | Score 20–39. Unsigned executable, newly downloaded installer in Downloads. | Logged silently | None |
| `SUSPICIOUS` | Score 40–59. Disguised double extension, execution from temp directory, anomaly signals. | Logged, elevated for review | Action Center notification |
| `THREAT` | Score 60–79. Script execution in hidden folder, multiple high-risk indicators. | Action recommended | High-priority notification |
| `CONFIRMED_MALWARE` | Score 80–100, or a confirmed Defender detection. | Immediate alert / quarantine | Critical security alert |

### 4. Quarantine Vault

- **Isolated storage** — suspicious files are moved out of their original directories into a secure vault (`data/quarantine/`).
- **SHA-256 integrity verification** — hashes are calculated and recorded before and after quarantine.
- **Safe restoration** — restoring a file recalculates its hash to confirm it was not altered before returning it to its original path.
- **Database tracking** — all quarantine events, timestamps, locations, and resolutions are tracked in SQLite.

### 5. Windows Temp and Junk Cleaner

```text
Resolve %TEMP%, %TMP%, %WINDIR%\Temp, %LOCALAPPDATA%\CrashDumps
                        │
                        ▼
            Inspect File Age (>24 Hours)
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
 [ Age < 24 Hours ]            [ Age >= 24 Hours ]
(Active: Preserved)           (Stale: Cleanup Candidate)
                                        │
                                        ▼
                            [ Safety Engine Gating ]
                                        │
                                        ▼
                            [ Non-Destructive Delete ]
                       (PermissionError / In-Use -> Skipped)
                                        │
                                        ▼
                       [ Prune Empty Subdirectories ]
                                        │
                                        ▼
                           [ Log Telemetry to DB ]
```

- **Target locations** — user temp (`%TEMP%` / `%TMP%`), Windows system temp (`%WINDIR%\Temp`), and application crash dumps (`%LOCALAPPDATA%\CrashDumps`).
- **Age threshold filter** — skips files modified within the last 24 hours to avoid interfering with active installers or running sessions.
- **Locked-file resilience** — handles `PermissionError` and `OSError` without force-terminating processes; locked files are bypassed and logged.
- **Empty directory pruning** — removes leftover empty subdirectories while preserving the root directory itself.
- **Dry-run safety** — cleanup runs in simulation mode by default, showing proposed space recovery before any live deletion.
- **Clean separation** — cleanup is a storage-hygiene feature only, and is never routed through the threat-detection pipeline.

### 6. Windows Action Center Notifications

- **Native toast integration** — dispatches native Windows 10/11 toasts via the Windows Notification Subsystem (`windows_toasts`).
- **Interactive quick actions** — security toasts include inline buttons (Quarantine, Leave it alone, View details), with an in-app dialog fallback if toasts are unavailable.
- **Anti-spam suppression** — configurable cooldown (`cooldown_seconds: 120`) and aggregation windows (`aggregate_window_seconds: 300`) prevent duplicate notification storms.

### 7. Native Control Center

A dark-themed desktop interface with eight management tabs:

| Tab | Functionality |
|---|---|
| Overview | Protection status, monitoring state, metric cards, quick actions, activity digest. |
| Security Scan | On-demand scanning with live progress, risk score badges, findings table, one-click quarantine. |
| Junk & Temp Cleanup | Candidate discovery, categorized results (safe to clean, in use, too recent, protected, skipped), space recovery metrics. |
| Quarantine | Vault table with original locations, detection reasons, severity, timestamps, hashes, restore/delete actions. |
| Activity | Searchable, filterable audit trail of security events, process spawns, cleanup runs, and logs. |
| Settings | Controls for monitoring, detection, cleanup, safety, startup, plus a raw YAML policy editor with schema validation. |
| System Health | Ten-subsystem diagnostic checklist with pass/warning/fail status and latency. |
| About | Version, architecture notes, database path, guardian mode, safety rules, project metadata. |

---

## Security Model

Ghost OS follows ten foundational security principles:

1. **Multi-signal context over single heuristics** — no single factor (e.g. being unsigned or located in Downloads) is ever treated as confirmed malware on its own.
2. **Defender independence and collaboration** — Microsoft Defender results are treated as authoritative alongside local heuristics, without replacing antivirus engines.
3. **Protected boundaries** — critical directories (`C:\Windows`, `C:\Program Files`) and processes (`explorer.exe`, `lsass.exe`, `csrss.exe`, `MsMpEng.exe`) are hard-coded as immutable.
4. **Isolated cleanup pipeline** — temp-file cleanup and malware detection are fully decoupled.
5. **No forceful process termination during cleanup** — files in use by a process are skipped, never force-closed.
6. **Explicit user authorization** — destructive operations require confirmation via toast actions or Control Center dialogs.
7. **Safe dry-run default** — `safety.dry_run: true` by default, so actions can be evaluated before any live change.
8. **Zero console flashing** — background process calls use `CREATE_NO_WINDOW` and hidden process creation flags.
9. **Local data storage** — telemetry and events are written to a local SQLite database (`data/telemetry.db`).
10. **Defensive scope only** — no kernel filter drivers, no raw network packet interception.

## System Architecture

```text
ghost_os_main.py (SingleInstance Guard & Startup Bootstrap)
      │
      ▼
   GhostCore (Central Subsystem Coordinator)
      │
      ├── Sensors & Watchers
      │     ├── SystemSensor (psutil CPU, RAM, Disk, IO sampling)
      │     ├── FileWatcher (watchdog file event monitor + thread pool)
      │     └── ProcessWatcher (Snapshot diffing & spawn inspection)
      │
      ├── Intelligence & Detection
      │     ├── ThreatSentinel (Bounded concurrency coordinator)
      │     ├── RuleEngine (Heuristics, extensions, digital signatures)
      │     ├── DefenderScanner (MpCmdRun.exe background scanner)
      │     └── AnomalyDetector (Scikit-learn Isolation Forest)
      │
      ├── Decision & Policy Gate
      │     ├── DecisionEngine (Risk scoring & action mapping)
      │     └── SafetyEngine (Protected paths, system processes, dry_run)
      │
      ├── Actions & Storage
      │     ├── SystemCleaner (Safe Windows temp/junk cleanup pipeline)
      │     ├── QuarantineManager (Vault isolation & SHA-256 restore)
      │     ├── Notifier (Native Windows Action Center toasts)
      │     └── DBManager (SQLite persistent audit logging & metrics)
      │
      └── User Interface
            ├── TrayApp (System tray presence & menu actions)
            └── ControlCenterManager / ControlCenterApp (Tkinter Native UI)
```

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.10+ | Core runtime and engine logic |
| User interface | Tkinter / ttk | Native dark-themed Control Center |
| System tray | `pystray` + `Pillow` | Background presence and tray actions |
| File monitoring | `watchdog` | Filesystem event monitoring |
| Process and metrics | `psutil` + `pywin32` | Process snapshotting and system metrics |
| Security scanning | Microsoft Defender CLI | Malware scanning via `MpCmdRun.exe` |
| Digital signatures | Windows Authenticode | Publisher and signature verification |
| Notifications | `windows_toasts` | Native Windows 10/11 Action Center toasts |
| Database | SQLite3 | Local storage for events and telemetry |
| Configuration | `ruamel.yaml` | Policy configuration with schema validation |
| Packaging | PyInstaller 6.x | Standalone Windows binary |
| Installer | Inno Setup 6.x | Windows setup installer with autostart |
| Testing | `pytest` | Unit and integration test suite |

## Installation

**Option 1 — Windows Installer (recommended)**

1. Download the latest `GhostOS-Setup.exe` from [GitHub Releases](https://github.com/bk5859200-blip/Ghost-OS/releases).
2. Run the installer and choose an installation path and startup options.
3. Launch Ghost OS from the Start Menu or desktop shortcut. The Control Center opens automatically and background monitoring begins immediately.

**Option 2 — Portable Archive**

1. Download `GhostOS-portable.zip` from [GitHub Releases](https://github.com/bk5859200-blip/Ghost-OS/releases).
2. Extract to any directory.
3. Run `GhostOS.exe`.

> Release packages are provided through GitHub Releases when published. To build from source, see [Developer Setup](#developer-setup).

## Developer Setup

**Prerequisites**

- Windows 10 or 11 (x64)
- Python 3.10–3.14
- Git for Windows

**Setup**

```powershell
# Clone the repository
git clone https://github.com/bk5859200-blip/Ghost-OS.git
cd "Ghost-OS"

# Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python ghost_os_main.py
```

## Testing

```powershell
pytest tests/ -v
```

```text
======================= 108 passed in 88.60s (0:01:28) ========================
```

- **Cleaner unit tests** (`tests/test_cleaner.py`) — dynamic root discovery, age filtering, locked-file resilience, empty directory pruning, dry-run execution.
- **Threat classification acceptance tests** (`tests/test_threat_distinction_acceptance.py`) — seven real-world fixtures verifying clean/unsigned software is never flagged as confirmed malware.
- **Pipeline integration tests** (`tests/test_integration_pipeline.py`) — file arrival → Threat Sentinel → Decision Engine → Quarantine → SHA-256 restore → DB logging.
- **UI tests** (`tests/test_ui.py`) — Control Center instantiation, tab switching, hide-to-tray lifecycle.

> Automated tests run in isolated environments to verify logic correctness. Live Windows runtime behavior across OS configurations is evaluated separately during release testing.

## Building

**Standalone executable and portable zip**

```powershell
python build_package.py
```

Cleans stale artifacts, runs PyInstaller with required hidden imports and version metadata, generates `dist/GhostOS/GhostOS.exe`, builds `dist/GhostOS-portable.zip`, computes SHA-256 checksums, and writes `dist/release_manifest.json`.

**Inno Setup Windows installer**

```powershell
python installer/build_installer.py
```

Locates `ISCC.exe` (Inno Setup 6), compiles `installer/ghost_os_setup.iss`, and generates `dist/GhostOS-Setup.exe`.

## Project Structure

```text
Ghost-OS/
├── assets/                       # Icons, logos, and UI screenshots
│   ├── ghost_os.ico
│   ├── ghost_os.png
│   └── screenshot_overview.png
├── config/                       # Configuration templates
│   └── policy.yaml               # Authoritative guardian policy configuration
├── installer/                    # Inno Setup installer definitions
│   ├── build_installer.py        # Automated ISCC compilation script
│   └── ghost_os_setup.iss        # Inno Setup installer script
├── src/                          # Application source code
│   ├── actions/                  # Cleanup, quarantine, scan, and diagnostics jobs
│   │   ├── cleaner.py            # Windows Temp & Junk Cleaner engine
│   │   ├── diagnostics_job.py    # Subsystem diagnostics evaluation
│   │   ├── quarantine_manager.py # Vault isolation & SHA-256 verification
│   │   └── scan_job.py           # On-demand multi-folder scanner
│   ├── actuators/                # Memory and disk actuation helpers
│   ├── autostart/                # Windows Registry autostart manager
│   ├── core/                     # Core runtime, config loader, logger, lifecycle
│   │   ├── config_loader.py      # Schema-validated policy loader
│   │   ├── ghost_core.py         # Central coordinator
│   │   ├── path_manager.py       # Safe path resolver
│   │   ├── proc_utils.py         # Console-less hidden process execution
│   │   └── single_instance.py    # Windows Named Mutex single-instance guard
│   ├── database/                 # SQLite manager and schema migrations
│   │   └── db_manager.py
│   ├── decision/                 # Risk synthesis and safety enforcement
│   │   ├── decision_engine.py    # Multi-signal risk synthesis & mapping
│   │   └── safety_engine.py      # Protected paths, process guards, dry-run
│   ├── intelligence/              # Threat inspection and scoring engines
│   │   ├── anomaly_detector.py   # Machine learning isolation forest
│   │   ├── defender_scanner.py   # Microsoft Defender MpCmdRun CLI integration
│   │   ├── rule_engine.py        # Explainable heuristic risk scoring
│   │   ├── signature_verifier.py # Authenticode digital signature verifier
│   │   └── threat_sentinel.py    # Inspection worker coordinator
│   ├── notifications/            # Windows Action Center toast notifications
│   │   └── notifier.py
│   ├── processes/                # Process snapshotting and anomaly analysis
│   ├── sensors/                  # System resource telemetry collector
│   ├── tray/                     # System tray application and menus
│   │   └── tray_app.py
│   ├── ui/                       # Native Tkinter Control Center
│   │   └── control_center.py     # Eight-tab Control Center UI & dialogs
│   └── watchers/                 # Filesystem and process monitors
├── tests/                        # Automated pytest test suite (108 tests)
├── build_package.py              # PyInstaller packaging automation script
├── ghost_os_main.py              # Application entry point
├── requirements.txt              # Production and development dependencies
├── version_info.txt              # Windows binary version resource metadata
└── README.md                     # Project documentation
```

## Configuration

Ghost OS is configured via `config/policy.yaml`, validated against a schema at startup:

```yaml
ghost:
  startup: true                   # Enable/disable Windows login autostart

monitoring:
  system_interval_seconds: 2      # Telemetry polling interval (seconds)
  process_interval_seconds: 5     # Process snapshot diffing interval (seconds)
  db_cleanup_days: 7              # SQLite telemetry retention window (days)

thresholds:
  cpu:
    critical_percent: 92.0
    consecutive_ticks: 3
  memory:
    critical_percent: 95.0
  disk:
    warning_percent: 90.0

notifications:
  enabled: true
  cooldown_seconds: 120           # Minimum cooldown between identical notifications
  aggregate_window_seconds: 300   # Repeated events grouped in time window

watch_folders:
  - "%USERPROFILE%\\Downloads"
  - "%USERPROFILE%\\Desktop"
  - "%TEMP%"

cleanup:
  enabled: true
  require_confirmation: true      # Propose cleanup via notification instead of silent execution
  stale_installer_days: 30
  stale_temp_days: 14

security:
  behavioral_monitoring: true
  protected_processes:
    - "explorer.exe"
    - "winlogon.exe"
    - "csrss.exe"
    - "MsMpEng.exe"               # Microsoft Defender
    - "python.exe"
  protected_paths:
    - "C:\\Windows"
    - "C:\\Program Files"
    - "C:\\Program Files (x86)"

safety:
  dry_run: true                   # Default ON: simulate actions without modifying disk
```

## Windows Startup

When `ghost.startup: true`, Ghost OS registers itself under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

- **Unprivileged execution** — runs under standard user privileges without requiring UAC elevation at startup.
- **Seamless boot lifecycle** — initializes silently, starts background monitoring, docks in the system tray, and opens the Control Center.

## Privacy and Local-First Design

- **Local operation** — monitoring, telemetry, and threat scoring execute entirely on the local machine.
- **Local database storage** — monitoring events, process history, and metrics are stored in `data/telemetry.db`.
- **No third-party analytics** — no advertising frameworks or commercial tracking SDKs are embedded.

## Limitations

Ghost OS is an auxiliary guardian and system-hygiene tool, not a complete enterprise security suite.

- **Not an antivirus replacement** — runs alongside and leverages Microsoft Defender; does not replace signature-based antivirus or enterprise EDR platforms.
- **User-space monitoring** — runs in Windows user space without kernel-level minifilter drivers.
- **Heuristic detections** — rule heuristics are context-sensitive and can produce false positives on unsigned or niche developer tools.
- **Locked file retention** — files locked by active processes are skipped during cleanup until the owning process terminates.
- **Platform support** — Windows 10 and 11 (64-bit) only.

## Roadmap

- Reputation intelligence caching — local caching of verified developer certificates and package hashes to speed up scans.
- Windows Event Tracing (ETW) integration — optional low-overhead process spawn auditing.
- Advanced memory profiling — interactive per-process memory working-set visualization in the Control Center.
- Expanded notification filtering — per-folder and per-category rules in the Policy Editor.
- Signed release binaries — automated CI workflow with Authenticode code signing for release installers.

## Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-new-feature`.
3. Commit your changes: `git commit -m "feat: add support for custom temp paths"`.
4. Run the test suite: `pytest tests/ -v`.
5. Push your branch and open a pull request describing your changes.

## License

No license is currently specified for this repository. Until a `LICENSE` file is added, the code defaults to all rights reserved — others may view the source but have no explicit permission to reuse, modify, or redistribute it.

## Responsible Use

Ghost OS is intended solely for defensive endpoint observation, authorized security monitoring, and routine Windows storage maintenance.
