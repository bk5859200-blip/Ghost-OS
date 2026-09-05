import os
import subprocess
import pystray
from PIL import Image, ImageDraw

from src.core.path_manager import PathManager
from src.core.ghost_core import (
    STATE_NORMAL, STATE_WATCHING, STATE_ATTENTION,
    STATE_PROTECTING, STATE_PAUSED, STATE_ERROR, STATE_STARTING
)
from src.ui.control_center import ControlCenterManager


def _build_ghost_icon(color=(140, 120, 255)):
    """Loads bundled Ghost icon or falls back to procedural ghost silhouette."""
    icon_path = PathManager.get_bundled_resource_path("assets/ghost_os.png")
    if os.path.exists(icon_path):
        try:
            return Image.open(icon_path)
        except Exception:
            pass

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((10, 8, 54, 48), fill=color)
    draw.rectangle((10, 30, 54, 52), fill=color)
    for cx in (18, 30, 42, 54):
        draw.ellipse((cx - 6, 44, cx + 4, 56), fill=color)
    draw.ellipse((20, 20, 26, 28), fill=(20, 20, 30, 255))
    draw.ellipse((38, 20, 44, 28), fill=(20, 20, 30, 255))
    return img


class TrayApp:
    """
    Primary manual presence point for Ghost OS in the Windows notification area.
    Provides instant access to the native Control Center, scans, quarantine, and settings.
    """

    STATE_ICONS = {
        STATE_NORMAL: "👻 NORMAL",
        STATE_WATCHING: "👻 WATCHING",
        STATE_ATTENTION: "⚠ ATTENTION",
        STATE_PROTECTING: "🛡 PROTECTING",
        STATE_PAUSED: "⏸ PAUSED",
        STATE_ERROR: "❌ ERROR",
        STATE_STARTING: "⏳ STARTING"
    }

    def __init__(self, ghost_core, quarantine_dir=None):
        self.core = ghost_core
        self.quarantine_dir = quarantine_dir or PathManager.get_quarantine_dir()
        self.control_center = ControlCenterManager(self.core)
        self.core.ui_show_tab_callback = self.control_center.show
        self.icon = None

    def _open_native_folder(self, folder_path):
        """Opens a local folder in Windows Explorer."""
        abs_path = os.path.abspath(folder_path)
        os.makedirs(abs_path, exist_ok=True)
        try:
            if os.name == 'nt':
                os.startfile(abs_path)
            else:
                from src.core.proc_utils import popen_hidden
                popen_hidden(['xdg-open', abs_path])
        except Exception:
            pass

    def _status_text(self, item):
        state = self.core.get_health_state()
        state_label = self.STATE_ICONS.get(state, f"● {state}")
        if not self.core.running:
            return "⏸ Protection Paused"
        return f"{state_label}"

    def _open_control_center(self, icon, item):
        self.control_center.show("overview")

    def _quick_scan(self, icon, item):
        self.control_center.show("scan")

    def _run_cleanup(self, icon, item):
        self.core.propose_cleanup()

    def _open_quarantine(self, icon, item):
        self.control_center.show("quarantine")

    def _view_activity(self, icon, item):
        self.control_center.show("activity")

    def _open_settings(self, icon, item):
        self.control_center.show("settings")

    def _open_diagnostics(self, icon, item):
        self.control_center.show("diagnostics")

    def _pause_monitoring(self, icon, item):
        self.core.pause()
        if self.icon:
            self.icon.update_menu()

    def _resume_monitoring(self, icon, item):
        self.core.resume()
        if self.icon:
            self.icon.update_menu()

    def _exit(self, icon, item):
        self.core.stop()
        icon.stop()

    def build_menu(self):
        return pystray.Menu(
            pystray.MenuItem(self._status_text, lambda i, it: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Control Center", self._open_control_center, default=True),
            pystray.MenuItem("Quick Scan", self._quick_scan),
            pystray.MenuItem("Activity History", self._view_activity),
            pystray.MenuItem("Quarantine Manager", self._open_quarantine),
            pystray.MenuItem("Clean System", self._run_cleanup),
            pystray.MenuItem("System Diagnostics", self._open_diagnostics),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Pause Monitoring", self._pause_monitoring, visible=lambda item: self.core.running),
            pystray.MenuItem("Resume Monitoring", self._resume_monitoring, visible=lambda item: not self.core.running),
            pystray.MenuItem("Settings", self._open_settings),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit Ghost OS", self._exit),
        )

    def run(self):
        self.icon = pystray.Icon("GhostOS", _build_ghost_icon(), "Ghost OS 👻", self.build_menu())
        self.icon.run()
