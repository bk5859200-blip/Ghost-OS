# Ghost OS 👻 — Native Windows Background Guardian

> **Ghost watches silently. Ghost thinks before acting. Ghost acts safely. Ghost tells you what happened.**

Ghost OS is a persistent, local-first Windows background guardian. It starts with Windows, lives quietly in the system tray, continuously observes system, process, and filesystem activity, detects suspicious or unwanted clutter, safely maintains the system, remembers meaningful events, and communicates through native Windows notifications.

Ghost OS is **not** an antivirus replacement and does **not** replace Microsoft Defender / Windows Security. It complements it by providing system awareness, behavioral observation, safe temporary cleanup, explainable risk scoring, and persistent event memory.

---

## 🏗 Architecture

```text
                         👻 GHOST OS
                              │
                         GHOST CORE
                              │
       ┌──────────────────────┼──────────────────────┐
       │                      │                      │
       ▼                      ▼                      ▼
 FILE WATCHER           PROCESS WATCHER        SYSTEM MONITOR
 (Downloads/Desktop)    (Parent/Child Diff)    (CPU/RAM/Disk/Net)
       │                      │                      │
       └──────────────────────┼──────────────────────┘
                              │
                              ▼
                       EVENT PIPELINE
                              │
                              ▼
                     INTELLIGENCE ENGINE
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         RULE ENGINE     BASELINE ENGINE   ANOMALY ENGINE
         (Explainable)   (Rolling Z-score) (Isolation Forest)
              │               │               │
              └───────────────┼───────────────┘
                              │
                              ▼
                       DECISION ENGINE
                              │
                              ▼
                        SAFETY ENGINE
                   (Protected Paths/Procs & Dry Run)
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
            CLEANUP       QUARANTINE      NOTIFY
         (Temp/Cache)    (Isolation/Hash) (Native Toasts)
               │              │              │
               └──────────────┼──────────────┘
                              ▼
                         GHOST MEMORY
                              │
                              ▼
                            SQLite
                              │
                              ▼
                    "While You Were Away"
                              │
                              ▼
                         👻 TRAY APP
                              │
                              ▼
                            USER
```

---

## 🛡 Safety Model

Every action in Ghost OS follows a strict 9-step pipeline:

```text
EVENT → NORMALIZE → ANALYZE → CLASSIFY → DECIDE → SAFETY CHECK → ACT → VERIFY → NOTIFY → REMEMBER
```

### Dry Run Default
Dry-run mode is enabled by default (`safety.dry_run: true` in `config/policy.yaml`). In this mode:
* Suspicious files and clutter are detected, analyzed, and scored.
* User notifications and activity logs are generated.
* **No files are deleted or quarantined without safety verification and explicit confirmation.**

### Protected Resources
Ghost OS enforces strict immutability for critical system assets:
* **Paths**: `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, and User Personal Documents.
* **Processes**: `explorer.exe`, `winlogon.exe`, `csrss.exe`, `services.exe`, `lsass.exe`, `MsMpEng.exe` (Defender), `python.exe`, `powershell.exe`, and 10+ core system processes.
* **Path Traversal Protection**: All operations verify that real target paths resolve strictly within authorized cleanup or quarantine roots.

---

## 🚀 Setup & Installation

### Prerequisites
* Windows 10 or Windows 11 (64-bit)
* Python 3.10+ (tested on Python 3.14)

### Quick Start

```powershell
# 1. Clone repository & navigate to directory
cd "d:\Document\GhostOS\GHOST OS"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch Ghost OS
python ghost_os_main.py
```

The Ghost icon (`👻`) will appear in your Windows System Tray (check the taskbar overflow arrow `^`).

---

## 🔔 Native Notifications & System Tray

Ghost OS requires **no web browser, no dashboard, and no local webserver**.

### System Tray Menu
* **Status Indicator**: `👻 NORMAL`, `👻 WATCHING`, `⚠ ATTENTION`, `🛡 PROTECTING`, `⏸ PAUSED`, `❌ ERROR`.
* **Quick Scan**: On-demand scan of Downloads, Desktop, Temp, and Startup directories.
* **Clean System**: Displays preview of removable temporary clutter and prompts for confirmation.
* **Activity**: Generates and opens a local text digest of recent events and anomalies.
* **Quarantine**: Opens the sandboxed quarantine folder in Windows Explorer.
* **Pause / Resume Monitoring**: Temporarily suspend or resume active file and process monitoring.
* **Settings**: Opens `config/policy.yaml` in your default text editor.
* **Exit**: Cleanly shuts down background workers and releases system mutexes.

### "While You Were Away" Digest
When you return, Ghost OS summarizes meaningful events recorded in SQLite memory:
```text
==================================================
           GHOST OS — ACTIVITY DIGEST             
==================================================
Health State:         WATCHING
Status Assessment:    Everything is stable.
Time Window:          Past 24 hours

--- SUMMARY OF EVENTS ---
Cleanups Run:         1
Disk Space Saved:     842.0 MB
Process Starts Seen:  34
Suspicious Files:     0
Files Quarantined:    0
Anomalies Flagged:    0

Ghost OS is operating silently in the background.
==================================================
```

---

## 🧪 Running Automated Tests

Ghost OS includes an extensive unit and integration test suite executing in isolated temporary directories:

```powershell
pytest tests/ -v
```

---

## 📦 Standalone Executable & Windows Installer

Ghost OS v1.0.0 is packaged as a standard Windows desktop application.

### 1. Build Standalone Executable & Portable ZIP
```powershell
python build_package.py
```
- **Executable**: `dist/GhostOS/GhostOS.exe` (Windowless background binary with embedded icon & version resource)
- **Portable ZIP**: `dist/GhostOS-portable.zip`

### 2. Build Windows Installer (`GhostOS-Setup.exe`)
```powershell
python installer/build_installer.py
```
- **Installer**: `dist/GhostOS-Setup.exe` (Inno Setup installer with modern wizard, Windows autostart option, Start Menu shortcuts, and uninstaller)

---

## 🛠 Installation & Uninstallation

### Installing Ghost OS
1. Run `GhostOS-Setup.exe`.
2. Select your preferred installation options (e.g. *Start Ghost OS with Windows*).
3. Click **Install**.
4. Once finished, Ghost OS will appear in your system tray (`👻`).

### Uninstallation
1. Open **Windows Settings** > **Apps** > **Installed apps** (or run `Uninstall Ghost OS` from the Start Menu).
2. Click **Uninstall**.
3. The uninstaller will automatically terminate any running `GhostOS.exe` processes, remove application files, delete Start Menu shortcuts, and clean up the autostart registry entry.
4. User history and quarantine logs in `%LOCALAPPDATA%\GhostOS` are safely preserved.

---

## 🧪 Running Automated Tests

Ghost OS includes an extensive unit and integration test suite executing in isolated temporary directories:

```powershell
pytest tests/ -v
```
**Current Baseline**: 62 / 62 Tests Passing (100%).

---

## 📄 License & Integrity

Ghost OS is designed as a complementary, privacy-first Windows desktop utility. All data, telemetry, and logs remain 100% on your local machine. Ghost OS does not send telemetry to the cloud.
