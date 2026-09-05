# -*- coding: utf-8 -*-
"""
Compiles GhostOS-Setup.exe using Inno Setup (ISCC.exe).
Usage:
    python installer/build_installer.py
"""

import os
import subprocess
import sys


def find_iscc():
    """Locates the Inno Setup compiler executable (ISCC.exe)."""
    candidates = [
        r"C:\Users\bharg\AppData\Local\Programs\Inno Setup 6\ISCC.exe",
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ]
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        candidates.insert(0, os.path.join(local_app_data, "Programs", "Inno Setup 6", "ISCC.exe"))

    for path in candidates:
        if os.path.exists(path):
            return path

    try:
        res = subprocess.run(["where", "ISCC.exe"], capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout.strip().splitlines()[0]
    except Exception:
        pass

    return None


def build_installer():
    print("==================================================")
    print("      GHOST OS -- WINDOWS INSTALLER BUILDER       ")
    print("==================================================")

    iscc_path = find_iscc()
    if not iscc_path:
        print("[ERROR] Inno Setup compiler (ISCC.exe) not found!")
        return 1

    print(f"Found Inno Setup Compiler: {iscc_path}")

    iss_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "ghost_os_setup.iss"))
    if not os.path.exists(iss_file):
        print(f"[ERROR] Inno Setup script not found: {iss_file}")
        return 1

    cmd = [iscc_path, iss_file]
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd)

    if result.returncode == 0:
        setup_exe = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dist", "GhostOS-Setup.exe"))
        if os.path.exists(setup_exe):
            size_bytes = os.path.getsize(setup_exe)
            print(f"\n[SUCCESS] Installer successfully built!")
            print(f"Location:  {setup_exe}")
            print(f"File Size: {size_bytes:,} bytes ({size_bytes / (1024*1024):.2f} MB)")
        else:
            print(f"\n[WARNING] ISCC exited with 0 but {setup_exe} was not found.")
    else:
        print(f"\n[FAILURE] Inno Setup compilation failed with exit code {result.returncode}.")

    return result.returncode


if __name__ == "__main__":
    sys.exit(build_installer())
