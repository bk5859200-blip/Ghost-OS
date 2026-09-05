import os
import shutil
import subprocess
import sys
import zipfile


def build():
    print("==================================================")
    print("        GHOST OS — STANDALONE BUILD SCRIPT        ")
    print("==================================================")

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
        print("\n[SUCCESS] Build completed successfully. Output located in 'dist/GhostOS/'.")

        # Create portable zip archive
        zip_path = os.path.join("dist", "GhostOS-portable.zip")
        print(f"Creating portable release archive: {zip_path}...")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            dist_dir = os.path.join("dist", "GhostOS")
            for root, dirs, files in os.walk(dist_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, "dist")
                    zf.write(file_path, rel_path)
        print(f"[SUCCESS] Portable release archive created: {zip_path} ({os.path.getsize(zip_path)} bytes)")
    else:
        print(f"\n[FAILURE] Build failed with exit code {result.returncode}.")

    return result.returncode


if __name__ == "__main__":
    sys.exit(build())
