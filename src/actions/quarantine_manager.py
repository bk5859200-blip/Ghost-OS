import os
import shutil
import uuid
import hashlib
import logging
from src.database.db_manager import DBManager
from src.core.path_manager import PathManager

logger = logging.getLogger("ghost.actions.quarantine")


class QuarantineManager:
    """
    Safely isolates suspicious files in a sandboxed quarantine directory.
    Stores comprehensive metadata (SHA-256 hash, original path, timestamp, size) in SQLite.
    Supports secure restoration.
    """

    def __init__(self, quarantine_dir=None, db_mgr=None):
        self.quarantine_dir = quarantine_dir or PathManager.get_quarantine_dir()
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.db_mgr = db_mgr or DBManager()

    def _calculate_sha256(self, file_path):
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def quarantine_file(self, event_id, file_path, reason="Suspicious activity detected"):
        """
        Moves file_path into quarantine folder under a UUID-prefixed name.
        Computes SHA-256 hash and logs metadata to database.
        Returns: (success: bool, quarantine_path: str|None, file_hash: str|None)
        """
        if not os.path.exists(file_path):
            logger.warning(f"Cannot quarantine nonexistent file: {file_path}")
            return False, None, None

        try:
            original_name = os.path.basename(file_path)
            safe_name = f"{uuid.uuid4().hex}__{original_name}.quarantine"
            dest_path = os.path.join(self.quarantine_dir, safe_name)

            file_hash = self._calculate_sha256(file_path)
            file_size = os.path.getsize(file_path)

            # Move file into isolation
            shutil.move(file_path, dest_path)

            # Log to quarantine table and resolve event
            self.db_mgr.log_quarantine(
                event_id=event_id,
                original_path=file_path,
                quarantine_path=dest_path,
                file_hash=file_hash,
                file_size=file_size
            )
            self.db_mgr.resolve_guardian_event(event_id, "quarantined")
            logger.info(f"Quarantined {file_path} -> {dest_path} (SHA-256: {file_hash})")

            return True, dest_path, file_hash
        except Exception as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return False, None, None

    def delete_file(self, event_id, file_path):
        """Permanent delete only upon explicit user instruction."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            self.db_mgr.resolve_guardian_event(event_id, "deleted")
            logger.info(f"User deleted flagged file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {file_path}: {e}")
            return False

    def ignore_event(self, event_id):
        """User chose to ignore the detection."""
        self.db_mgr.resolve_guardian_event(event_id, "ignored")
        logger.info(f"Guardian event {event_id} ignored by user.")

    def restore_file(self, quarantine_path, original_path):
        """Restores an isolated file back to its original location."""
        try:
            if not os.path.exists(quarantine_path):
                logger.warning(f"Quarantine file not found: {quarantine_path}")
                return False

            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(quarantine_path, original_path)

            self.db_mgr.mark_quarantine_restored(quarantine_path)
            logger.info(f"Restored file {quarantine_path} -> {original_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore {quarantine_path}: {e}")
            return False

    def list_quarantined(self):
        """Returns list of all active quarantined files on disk."""
        if not os.path.exists(self.quarantine_dir):
            return []
        return [
            os.path.join(self.quarantine_dir, f)
            for f in os.listdir(self.quarantine_dir)
            if os.path.isfile(os.path.join(self.quarantine_dir, f))
        ]
