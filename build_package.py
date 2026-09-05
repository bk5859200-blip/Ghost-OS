import os
import shutil
import subprocess
import sys
import json
import time
import hashlib
import zipfile


def get_git_commit():
    try:
        res = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def build():
    print("==================================================")
    print("        GHOST OS — STANDALONE BUILD SCRIPT        ")
    print("==================================================")

    # Clean stale build and dist directories
    print("[CLEAN] Stopping any running GhostOS processes...")
    if sys.platform == "win32":
        try:
            subprocess.run(["taskkill.exe", "/F", "/IM", "GhostOS.exe"],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(0.5)
        except Exception:
            pass

    print("[CLEAN] Removing stale build/ and dist/ artifacts...")
    if os.path.exists("build"):
        shutil.rmtree("build", ignore_errors=True)
    if os.path.exists("dist"):
        shutil.rmtree("dist", ignore_errors=True)

    # Ensure required build directories and assets exist
    os.makedirs("data", exist_ok=True)
    os.makedirs("config", exist_ok=True)
    os.makedirs("assets", exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--name", "GhostOS",
        "--icon", "assets/ghost_os.ico",
        "--version-file", "version_info.txt",
        "--add-data", "config;config",
        "--add-data", "assets;assets",
        "--hidden-import", "ruamel.yaml",
        "--hidden-import", "windows_toasts",
        "--hidden-import", "pystray",
        "--hidden-import", "watchdog",
        "--hidden-import", "sklearn",
        "--hidden-import", "scipy",
        "--hidden-import", "numpy",
        "--hidden-import", "pandas",
        "--hidden-import", "psutil",
        "--hidden-import", "PIL",
        "--hidden-import", "win32api",
        "--hidden-import", "winerror",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "ghost_os_main.py"
    ]

    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd)

    if result.returncode == 0:
        exe_path = os.path.join("dist", "GhostOS", "GhostOS.exe")
        if not os.path.exists(exe_path):
            print(f"\n[ERROR] PyInstaller succeeded but {exe_path} not found.")
            return 1

        exe_size = os.path.getsize(exe_path)
        exe_hash = calculate_sha256(exe_path)
        print("\n[SUCCESS] Standalone build completed successfully.")
        print(f"  EXE Location: {exe_path}")
        print(f"  EXE Size:     {exe_size:,} bytes ({exe_size / (1024*1024):.2f} MB)")
        print(f"  EXE SHA-256:  {exe_hash}")

        # Create portable zip archive
        zip_path = os.path.join("dist", "GhostOS-portable.zip")
        print(f"\nCreating portable release archive: {zip_path}...")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            dist_dir = os.path.join("dist", "GhostOS")
            for root, dirs, files in os.walk(dist_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, "dist")
                    zf.write(file_path, rel_path)

        zip_size = os.path.getsize(zip_path)
        zip_hash = calculate_sha256(zip_path)
        print(f"[SUCCESS] Portable release archive created: {zip_path}")
        print(f"  ZIP Size:    {zip_size:,} bytes ({zip_size / (1024*1024):.2f} MB)")
        print(f"  ZIP SHA-256: {zip_hash}")

        # Generate release manifest
        manifest = {
            "version": "1.0.0",
            "git_commit": get_git_commit(),
            "build_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "artifacts": {
                "standalone_exe": {
                    "path": "dist/GhostOS/GhostOS.exe",
                    "size_bytes": exe_size,
                    "sha256": exe_hash
                },
                "portable_zip": {
                    "path": "dist/GhostOS-portable.zip",
                    "size_bytes": zip_size,
                    "sha256": zip_hash
                }
            }
        }
        manifest_path = os.path.join("dist", "release_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2)
        print(f"[SUCCESS] Release manifest written to: {manifest_path}")

    else:
        print(f"\n[FAILURE] Build failed with exit code {result.returncode}.")

    return result.returncode


if __name__ == "__main__":
    sys.exit(build())

