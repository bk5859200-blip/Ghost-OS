# Ghost OS

**A local-first Windows background guardian for system monitoring, file activity, process activity, and threat detection.**

Ghost OS runs quietly in the background and continuously observes system activity while keeping runtime data on the local machine. It provides system telemetry, file and process monitoring, threat analysis, quarantine management, notifications, and controlled cleanup operations through a system-tray interface.

> Ghost OS is a monitoring and system-guardian project, not a replacement for Windows Defender or a commercial antivirus product.

---

## Features

### System Monitoring

* CPU and memory usage monitoring
* Disk and system telemetry
* Persistent local telemetry history
* Background monitoring with low-interaction operation

### File Monitoring

Ghost OS monitors selected user locations for relevant file activity, including:

* Downloads
* Desktop
* Temporary activity

File events can be evaluated by the threat-analysis pipeline before any protected action is considered.

### Process Monitoring

* Detects newly spawned processes
* Collects process telemetry
* Identifies suspicious process relationships
* Records relevant events for later analysis

### Threat Detection

Ghost OS uses a layered detection pipeline:

1. Rule-based analysis
2. Threat scoring
3. Windows Defender integration where appropriate
4. Decision Engine evaluation
5. Safety Engine authorization

Actions are deliberately separated from detection so that a detected event does not automatically imply that a destructive action will be performed.

### Quarantine

Suspicious files can be isolated into the local Ghost OS quarantine vault.

The quarantine system maintains integrity information so files can be verified and restored when appropriate.

### System Cleanup

Ghost OS can analyze temporary and unnecessary files and provide controlled cleanup operations.

Cleanup actions pass through the project's safety controls before execution.

### Notifications

The application can display Windows notifications for events such as:

* Information
* Warnings
* Security events
* Cleanup activity
* Quarantine activity
* Errors

### System Tray

Ghost OS is designed to run without a traditional application window.

The system tray provides access to the application's primary controls and status.

---

## Architecture

Ghost OS is organized into separate components so monitoring, analysis, decision making, and system actions remain isolated.

```text
                         Ghost OS
                            │
                     ┌──────┴──────┐
                     │   GhostCore  │
                     └──────┬──────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
 System Monitor       File Monitor        Process Monitor
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
                    Threat Sentinel
                            │
                            ▼
                     Decision Engine
                            │
                            ▼
                      Safety Engine
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          Quarantine      Cleaner      Notifications
                            │
                            ▼
                         SQLite
```

The separation is intentional: **observation → analysis → decision → action**.

---

## Project Structure

```text
Ghost-OS/
│
├── assets/
│   └── ghost_os.ico
│
├── config/
│   └── policy.yaml
│
├── installer/
│   ├── ghost_os_setup.iss
│   └── build_installer.py
│
├── src/
│   ├── intelligence/
│   ├── monitoring/
│   ├── processes/
│   ├── safety/
│   ├── quarantine/
│   ├── cleaner/
│   ├── database/
│   ├── notifications/
│   └── ...
│
├── tests/
│
├── build_package.py
├── ghost_os_main.py
├── requirements.txt
├── version_info.txt
└── README.md
```

---

## Requirements

### Supported Platform

* Windows 10/11
* 64-bit Windows recommended

### Development Requirements

* Python 3.11+
* Git
* Windows Defender / Microsoft Defender for Defender-backed scanning
* Inno Setup 6 for building the Windows installer

---

## Installation & User Distribution

### Recommended — Windows Installer (`GhostOS-Setup.exe`)

For standard users, **`GhostOS-Setup.exe`** is the primary, self-contained distribution package. It requires **no Python installation, no terminal commands, and no manual file copying**.

1. Download **`GhostOS-Setup.exe`** from the latest release.
2. Run `GhostOS-Setup.exe` and follow the setup wizard.
3. The installer automatically configures:
   * Application binaries in `%LOCALAPPDATA%\Programs\Ghost OS\`
   * Start Menu shortcut
   * Optional Desktop shortcut
   * Optional Windows Startup (auto-launch on user logon)
   * Isolated runtime telemetry and vault directories in `%LOCALAPPDATA%\GhostOS\`
   * Windows Uninstaller integration in Settings / Control Panel

### Portable Archive (`GhostOS-portable.zip`)

For standalone or offline environments without installation privileges:
1. Download and extract **`GhostOS-portable.zip`**.
2. Run `GhostOS.exe` directly.

### Developer Setup — Run From Source (Development Only)

Clone the repository and set up the local Python virtual environment:

```powershell
git clone https://github.com/bk5859200-blip/Ghost-OS.git
cd Ghost-OS
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run Ghost OS:

```powershell
python ghost_os_main.py
```

For a background/windowless launch:

```powershell
pythonw ghost_os_main.py
```

---

## Configuration

The default policy is located at:

```text
config/policy.yaml
```

Runtime data is stored separately under:

```text
%LOCALAPPDATA%\GhostOS\
```

Typical runtime data includes:

```text
GhostOS/
├── config/
├── data/
│   ├── telemetry.db
│   └── quarantine/
└── logs/
```

Ghost OS is designed to keep mutable runtime data outside the application installation directory.

---

## Safety

Ghost OS uses multiple safeguards around system actions.

The default configuration keeps destructive actions in **dry-run mode** unless explicitly configured otherwise.

Protected locations and processes are handled by the Safety Engine before an action can proceed.

The detection pipeline does not directly perform system modifications:

```text
Detection
    ↓
Decision Engine
    ↓
Safety Engine
    ↓
Action
```

This separation is intended to reduce accidental system changes.

---

## Testing

Run the complete test suite:

```powershell
pytest tests/ -v
```

Tests cover components including:

* Configuration loading
* Database management
* System monitoring
* Process monitoring
* File monitoring
* Threat detection
* Decision making
* Safety controls
* Quarantine
* Notifications
* Single-instance behavior
* Integration paths

Runtime validation and release-specific verification are documented separately in:

```text
FINAL_VALIDATION.md
RELEASE_VALIDATION.md
```

---

## Building

### Standalone Executable

```powershell
python build_package.py
```

The resulting executable is generated under:

```text
dist/GhostOS/
```

### Windows Installer

Install Inno Setup 6 and run:

```powershell
python installer/build_installer.py
```

The installer is generated under:

```text
dist/GhostOS-Setup.exe
```

---

## Design Goals

Ghost OS is built around a few simple principles:

**Local-first**
Runtime telemetry and application data remain on the local machine.

**Safety-first**
System actions are gated through explicit safety controls.

**Background operation**
Monitoring should continue without requiring a constantly open application window.

**Modular architecture**
Monitoring, intelligence, decisions, actions, and persistence are kept as separate components.

**Observable behavior**
Important system activity should be recorded so problems can be investigated rather than silently ignored.

---

## Limitations

Ghost OS should not be treated as a complete antivirus or endpoint-security solution.

Its threat detection capabilities depend on the configured detection rules, available system information, and Windows Defender integration.

Users should continue to use Windows Security and keep Windows and security definitions up to date.

---

## Development

Contributions and improvements are welcome.

Before submitting changes:

1. Keep changes focused.
2. Avoid bypassing the Safety Engine.
3. Add or update tests for behavioral changes.
4. Run the complete test suite.
5. Verify that background workers terminate cleanly.
6. Check that runtime data remains outside the installation directory.

---

## Roadmap

Planned development areas may include:

* Improved monitoring performance
* More robust background worker management
* Better diagnostics
* Expanded telemetry analysis
* Improved control-center interface
* Additional Windows integration
* More comprehensive runtime stress testing

---

## License

This project is currently under development.

License information will be added here when the project's distribution terms are finalized.

---

## Author

**Bhargav**

GitHub:
https://github.com/bk5859200-blip

---

<p align="center">
  <strong>Ghost OS</strong><br>
  Local-first Windows system guardian.
</p>
