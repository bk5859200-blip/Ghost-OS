import os
import shutil
import tempfile
import time
import logging

logger = logging.getLogger("ghost.actions.cleaner")


class SystemCleaner:
    """
    Safe cleanup pipeline:
      DISCOVER -> CLASSIFY -> SAFETY CHECK -> CALCULATE SIZE -> PREVIEW -> ACTION -> LOG
    Only operates on strictly verified disposable locations.
    """

    def __init__(self, safety_engine, db_mgr=None, require_confirmation=True):
        self.safety_engine = safety_engine
        self.db_mgr = db_mgr
        self.require_confirmation = require_confirmation

        home = os.path.expanduser("~")
        local_app_data = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        windows_dir = os.environ.get("SystemRoot", "C:\\Windows")

        self.disposable_roots = [
            tempfile.gettempdir(),
            os.path.join(windows_dir, "Temp"),
            os.path.join(local_app_data, "Temp"),
            os.path.join(local_app_data, "CrashDumps")
        ]

    def _classify_item(self, file_path):
        """Classifies a candidate into Temporary, Cache, or Crash dumps."""
        lower = file_path.lower()
        if lower.endswith(".dmp") or "crashdumps" in lower:
            return "Crash dumps"
        if "cache" in lower or lower.endswith(".tmp") or lower.endswith(".chk"):
            return "Cache"
        return "Temporary"

    def discover(self):
        """
        Discovers cleanup candidates across allowed disposable roots.
        Returns a list of dicts:
          [{'path': str, 'size': int, 'category': str, 'is_dir': bool}]
        """
        candidates = []
        for root in self.disposable_roots:
            if not os.path.exists(root):
                continue

            try:
                items = os.listdir(root)
            except OSError:
                continue

            for item in items:
                item_path = os.path.join(root, item)

                # Strictly validate that item resolves inside the allowed root
                if not self.safety_engine.validate_path(item_path, self.disposable_roots):
                    continue

                if self.safety_engine.is_path_protected(item_path):
                    continue

                try:
                    category = self._classify_item(item_path)
                    if os.path.isfile(item_path) or os.path.islink(item_path):
                        size = os.path.getsize(item_path)
                        candidates.append({
                            "path": item_path,
                            "size": size,
                            "category": category,
                            "is_dir": False
                        })
                    elif os.path.isdir(item_path):
                        size = 0
                        for dp, _, files in os.walk(item_path):
                            for f in files:
                                fp = os.path.join(dp, f)
                                if os.path.exists(fp) and not os.path.islink(fp):
                                    try:
                                        size += os.path.getsize(fp)
                                    except OSError:
                                        pass
                        candidates.append({
                            "path": item_path,
                            "size": size,
                            "category": category,
                            "is_dir": True
                        })
                except OSError:
                    continue

        return candidates

    def preview(self):
        """
        SCAN ONLY mode.
        Returns itemized preview without performing any deletions.
        """
        candidates = self.discover()
        total_bytes = sum(c["size"] for c in candidates)
        categories_breakdown = {
            "Temporary": 0.0,
            "Cache": 0.0,
            "Crash dumps": 0.0
        }

        for c in candidates:
            cat = c["category"]
            categories_breakdown[cat] = categories_breakdown.get(cat, 0.0) + (c["size"] / (1024 * 1024))

        return {
            "count": len(candidates),
            "size_mb": round(total_bytes / (1024 * 1024), 2),
            "categories": {k: round(v, 2) for k, v in categories_breakdown.items()},
            "candidates": candidates
        }

    def execute(self, candidates, batch_size=50, pause_between_batches=0.05):
        """
        Executes cleanup on pre-approved candidate list in responsive batches.
        Respects safety_engine dry_run mode.
        """
        files_removed, dirs_removed, bytes_recovered = 0, 0, 0
        categories_recovered = {"Temporary": 0, "Cache": 0, "Crash dumps": 0}

        for idx, c in enumerate(candidates, 1):
            path = c["path"]
            size = c["size"]
            category = c["category"]
            is_dir = c["is_dir"]

            allowed, reason = self.safety_engine.gate_action("cleanup_delete", path)
            if not allowed:
                logger.info(f"[DRY RUN / SAFE] Would remove: {path} | Category: {category} | Reason: Verified safe temporary item (no changes made)")
            else:
                try:
                    if not is_dir and (os.path.isfile(path) or os.path.islink(path)):
                        os.unlink(path)
                        files_removed += 1
                    elif is_dir and os.path.isdir(path):
                        shutil.rmtree(path)
                        dirs_removed += 1
                    bytes_recovered += size
                    categories_recovered[category] = categories_recovered.get(category, 0) + 1
                except Exception as e:
                    logger.warning(f"Could not remove locked or protected item {path}: {e}")

            if idx % batch_size == 0 and idx < len(candidates):
                time.sleep(pause_between_batches)

        space_mb = round(bytes_recovered / (1024 * 1024), 2)
        dry_run = self.safety_engine.dry_run

        if self.db_mgr:
            self.db_mgr.log_cleanup_event(
                files_removed=files_removed,
                dirs_removed=dirs_removed,
                space_recovered_mb=space_mb,
                categories=categories_recovered,
                dry_run=dry_run
            )

        result = {
            "files_removed": files_removed,
            "dirs_removed": dirs_removed,
            "space_recovered_mb": space_mb,
            "dry_run": dry_run,
            "categories_breakdown": categories_recovered
        }
        logger.info(f"Cleanup execution result: {result}")
        return result
