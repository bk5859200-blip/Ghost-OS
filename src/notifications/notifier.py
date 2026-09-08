import time
import os
import sys
import threading
import logging

logger = logging.getLogger("ghost.notifications")

# Notification categories (Master Spec Section 28)
CAT_INFO = "INFO"
CAT_WARNING = "WARNING"
CAT_SECURITY = "SECURITY"
CAT_CLEANUP = "CLEANUP"
CAT_QUARANTINE = "QUARANTINE"
CAT_RECOVERY = "RECOVERY"
CAT_ERROR = "ERROR"

GHOST_AUMID = "GhostOS.SystemGuardian.v1"


class Notifier:
    """
    Native Windows notification manager.
    Enforces duplicate suppression, cooldowns (120s), and event aggregation (300s window).
    Persists all alerts to SQLite for audit history and away digests.
    """

    def __init__(self, app_name=GHOST_AUMID, cooldown_seconds=120,
                 aggregate_window_seconds=300, enabled=True, db_mgr=None, fallback_alert_handler=None):
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(GHOST_AUMID)
            except Exception as e:
                logger.debug(f"AUMID registration error: {e}")

        self.app_name = app_name or GHOST_AUMID
        self.enabled = enabled
        self.cooldown_seconds = cooldown_seconds
        self.aggregate_window_seconds = aggregate_window_seconds
        self.db_mgr = db_mgr
        self.fallback_alert_handler = fallback_alert_handler
        self._last_sent = {}       # signal_key -> timestamp
        self._pending_counts = {}  # signal_key -> count
        self._lock = threading.Lock()
        self.toaster = None

        if self.enabled:
            try:
                from windows_toasts import InteractableWindowsToaster
                self.toaster = InteractableWindowsToaster(self.app_name)
            except Exception as e:
                logger.warning(f"Could not initialize Windows Toaster: {e}")
                self.toaster = None

    def _should_send(self, signal_key):
        """
        Evaluates cooldown and aggregation window.
        Returns: (send_now: bool, suppressed_count: int)
        """
        with self._lock:
            now = time.time()
            last = self._last_sent.get(signal_key, 0)
            if now - last < self.cooldown_seconds:
                self._pending_counts[signal_key] = self._pending_counts.get(signal_key, 0) + 1
                return False, self._pending_counts[signal_key]

            suppressed = self._pending_counts.pop(signal_key, 0)
            self._last_sent[signal_key] = now
            return True, suppressed

    def _show_toast(self, toast_obj):
        """Displays toast notification via Windows Action Center."""
        if self.toaster and toast_obj:
            try:
                self.toaster.show_toast(toast_obj)
                return True
            except Exception as e:
                logger.warning(f"Toast display failed: {e}")
        return False

    def _record(self, title, message, signal_key, severity, suppressed=0, delivered=True):
        if self.db_mgr:
            try:
                self.db_mgr.log_notification(
                    title=title,
                    message=message,
                    signal_key=signal_key,
                    severity=severity,
                    suppressed_count=suppressed,
                    delivered=delivered
                )
            except Exception as e:
                logger.warning(f"Failed to log notification in database: {e}")

    def notify_normal(self):
        """Normal / watching heartbeat notification."""
        if not self.enabled:
            return
        title = "👻 Ghost OS"
        message = "Everything looks normal.\nI'll keep watching."
        send_now, suppressed = self._should_send("status:normal")
        if not send_now:
            return

        toast = None
        if self.toaster:
            from windows_toasts import Toast
            toast = Toast([title, message])

        delivered = self._show_toast(toast)
        self._record(title, message, "status:normal", CAT_INFO, suppressed, delivered)

    def notify_info(self, title, message, signal_key=None, severity=CAT_INFO):
        if not self.enabled:
            return
        key = signal_key or f"info:{title}"
        send_now, suppressed = self._should_send(key)
        if not send_now:
            return

        final_msg = message
        if suppressed > 0:
            final_msg += f"\n(and {suppressed} similar update{'s' if suppressed > 1 else ''} in window)"

        toast = None
        if self.toaster:
            from windows_toasts import Toast
            toast = Toast([title, final_msg])

        delivered = self._show_toast(toast)
        self._record(title, final_msg, key, severity, suppressed, delivered)

    def notify_suspicious(self, file_path, risk_score, classification, reason):
        """Notification for suspicious or unusual file activity."""
        if not self.enabled:
            return

        title = "🔍 Ghost OS — Security Notice"
        filename = os.path.basename(file_path)
        display_class = str(classification).upper().replace("_", " ")
        message = (
            f"Suspicious activity observed:\n\n"
            f"File: {filename}\n"
            f"Classification: {display_class} ({risk_score}/100)\n"
            f"Reason: {reason}\n\n"
            f"No action taken. Logged for review."
        )

        key = f"suspicious:{file_path}"
        send_now, suppressed = self._should_send(key)
        if not send_now:
            return

        toast = None
        if self.toaster:
            from windows_toasts import Toast
            toast = Toast([title, message])

        delivered = self._show_toast(toast)
        self._record(title, message, key, CAT_SECURITY, suppressed, delivered)

    def alert_detection(self, event_id, file_path, reason, severity, on_response):
        """Actionable native Windows toast alert with Quarantine / Leave it alone / View details buttons."""
        if not self.enabled:
            return

        filename = os.path.basename(file_path)
        sev_upper = str(severity).upper()
        if "MALWARE" in sev_upper or "CRITICAL" in sev_upper:
            title = "🛡 Ghost OS — Confirmed Malware Alert"
        elif "THREAT" in sev_upper or "HIGH" in sev_upper:
            title = "⚠ Ghost OS — Potential Threat Detected"
        else:
            title = "🔍 Ghost OS — Security Review"

        display_class = sev_upper.replace("_", " ")
        message = f"File: {filename}\nLocation: {file_path}\nClassification: {display_class}\nReason: {reason}"

        key = f"alert:{event_id}:{file_path}"
        send_now, suppressed = self._should_send(key)
        if not send_now:
            return

        toast = None
        if self.toaster:
            from windows_toasts import Toast, ToastButton, ToastActivatedEventArgs
            toast = Toast([title, message])
            toast.AddAction(ToastButton("Quarantine", f"quarantine|{event_id}"))
            toast.AddAction(ToastButton("Leave it alone", f"ignore|{event_id}"))
            toast.AddAction(ToastButton("View details", f"details|{event_id}"))

            def _on_activated(activated_event: ToastActivatedEventArgs):
                try:
                    action, _ = activated_event.arguments.split("|", 1)
                except (AttributeError, ValueError):
                    action = "ignore"
                on_response(event_id, file_path, action)

            toast.on_activated = _on_activated

        delivered = self._show_toast(toast)
        self._record(title, message, key, CAT_SECURITY, suppressed, delivered)

        if not delivered and self.fallback_alert_handler:
            try:
                self.fallback_alert_handler(event_id, file_path, reason, severity)
            except Exception as e:
                logger.error(f"Fallback alert handler failed: {e}")

    def send_test_threat_notification(self, on_response=None):
        """Dispatches a safe synthetic test security alert to verify toast delivery and action handling."""
        event_id = f"test_evt_{int(time.time())}"
        test_file = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "invoice_sample.pdf.exe")
        reason = "Test Security Alert (Safe fixture) — Disguised executable extension (.pdf.exe)"
        severity = "HIGH"

        def _default_callback(eid, fp, act):
            logger.info(f"Test alert response received: event_id={eid}, action={act}")

        callback = on_response or _default_callback
        self.alert_detection(event_id, test_file, reason, severity, callback)
        return event_id

    def notify_quarantined(self, file_path, risk_score):
        if not self.enabled:
            return
        title = "🛡 Ghost OS"
        filename = os.path.basename(file_path)
        message = f"A suspicious file was isolated.\n\n{filename}\nThe original file is preserved in quarantine."

        toast = None
        if self.toaster:
            from windows_toasts import Toast
            toast = Toast([title, message])

        delivered = self._show_toast(toast)
        self._record(title, message, f"quarantine:{file_path}", CAT_QUARANTINE, 0, delivered)

    def notify_cleanup_proposal(self, count, size_mb, on_review, on_clean_now=None, on_later=None):
        if not self.enabled:
            return
        title = "👻 Ghost OS — Temporary Cleanup"
        message = f"Temporary files are ready to clean.\n{count} items ({size_mb:.1f} MB) recoverable."

        key = "cleanup:proposal"
        send_now, suppressed = self._should_send(key)
        if not send_now:
            return

        toast = None
        if self.toaster:
            from windows_toasts import Toast, ToastButton, ToastActivatedEventArgs
            toast = Toast([title, message])
            toast.AddAction(ToastButton("Review", "cleanup_review"))
            if on_clean_now:
                toast.AddAction(ToastButton("Clean Now", "cleanup_clean_now"))
            toast.AddAction(ToastButton("Later", "cleanup_later"))

            def _on_activated(activated_event: ToastActivatedEventArgs):
                arg = getattr(activated_event, "arguments", "")
                if arg == "cleanup_review":
                    if on_review:
                        on_review()
                elif arg == "cleanup_clean_now":
                    if on_clean_now:
                        on_clean_now()
                    elif on_review:
                        on_review()
                else:
                    if on_later:
                        on_later()

            toast.on_activated = _on_activated

        delivered = self._show_toast(toast)
        self._record(title, message, key, CAT_CLEANUP, suppressed, delivered)

    def notify_cleanup_complete(self, files_removed, space_recovered_mb):
        if not self.enabled:
            return
        title = "👻 Ghost OS"
        message = f"Cleanup completed.\n\n{files_removed} temporary files removed.\n{space_recovered_mb:.1f} MB recovered."

        toast = None
        if self.toaster:
            from windows_toasts import Toast
            toast = Toast([title, message])

        delivered = self._show_toast(toast)
        self._record(title, message, "cleanup:complete", CAT_CLEANUP, 0, delivered)

    def notify_paused(self):
        self.notify_info("⏸ Ghost OS", "Protection paused. Ghost will not actively monitor until resumed.", signal_key="pause:notif", severity=CAT_WARNING)

    def notify_resumed(self):
        self.notify_info("👻 Ghost OS", "Protection resumed. Watching system actively.", signal_key="resume:notif", severity=CAT_INFO)
