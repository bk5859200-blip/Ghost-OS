import os
import sys
import shutil

APP_NAME = "GhostOS"


class PathManager:
    """
    Centralized path resolver ensuring complete path independence for Ghost OS.
    Resolves writable runtime directories in %LOCALAPPDATA%\\GhostOS while
    accessing bundled read-only assets in packaged mode.
    """

    @staticmethod
    def get_repo_root():
        """Returns the project source root directory."""
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            return sys._MEIPASS
        return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    @staticmethod
    def get_app_data_dir():
        """Returns the writable per-user root application directory."""
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            local_app_data = os.path.expanduser("~")
        app_dir = os.path.join(local_app_data, APP_NAME)
        os.makedirs(app_dir, exist_ok=True)
        return app_dir

    @staticmethod
    def get_data_dir():
        d = os.path.join(PathManager.get_app_data_dir(), "data")
        os.makedirs(d, exist_ok=True)
        return d

    @staticmethod
    def get_logs_dir():
        d = os.path.join(PathManager.get_app_data_dir(), "logs")
        os.makedirs(d, exist_ok=True)
        return d

    @staticmethod
    def get_config_dir():
        d = os.path.join(PathManager.get_app_data_dir(), "config")
        os.makedirs(d, exist_ok=True)
        return d

    @staticmethod
    def get_quarantine_dir():
        d = os.path.join(PathManager.get_data_dir(), "quarantine")
        os.makedirs(d, exist_ok=True)
        return d

    @staticmethod
    def get_models_dir():
        d = os.path.join(PathManager.get_data_dir(), "models")
        os.makedirs(d, exist_ok=True)
        return d

    @staticmethod
    def get_database_path():
        return os.path.join(PathManager.get_data_dir(), "telemetry.db")

    @staticmethod
    def get_log_file_path():
        return os.path.join(PathManager.get_logs_dir(), "ghost_os.log")

    @staticmethod
    def get_bundled_resource_path(relative_path):
        """Resolves bundled asset path (works in both PyInstaller and source mode)."""
        base = PathManager.get_repo_root()
        return os.path.normpath(os.path.join(base, relative_path))

    @staticmethod
    def ensure_user_config():
        """
        Ensures a writable policy.yaml exists in the user's AppData directory.
        If missing, copies the bundled default policy.yaml.
        """
        user_config_path = os.path.join(PathManager.get_config_dir(), "policy.yaml")
        if not os.path.exists(user_config_path):
            bundled_config = PathManager.get_bundled_resource_path("config/policy.yaml")
            if os.path.exists(bundled_config):
                shutil.copy2(bundled_config, user_config_path)
            else:
                # If bundled not found, check source repo relative to cwd
                fallback = os.path.abspath("config/policy.yaml")
                if os.path.exists(fallback):
                    shutil.copy2(fallback, user_config_path)
        return user_config_path

    @staticmethod
    def is_packaged():
        return getattr(sys, "frozen", False)
