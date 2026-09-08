import os
import shutil
import tempfile
import time
import logging

logger = logging.getLogger("ghost.actions.cleaner")


class SystemCleaner:
    """
    Safe Windows Temporary / Junk File Cleanup Pipeline:
      DISCOVER -> CLASSIFY -> AGE FILTER -> SAFETY CHECK -> PREVIEW -> BATCH EXECUTE -> LOG

    Safety Guarantees:
      - Only operates on strictly verified Windows disposable locations (%TEMP%, %TMP%, %WINDIR%\\Temp, CrashDumps).
      - Applies age filtering (default > 24 hours) so active/recent temporary files are never disturbed.
      - Skips locked or in-use files gracefully without force-terminating any processes.
      - Never deletes disposable root directories or protected system files.
      - Gated by SafetyEngine and strictly honors dry_run mode.
      - Never classifies temporary/junk files as security threats.
    """

    def __init__(self, safety_engine, db_mgr=None, require_confirmation=True, min_age_hours=24):
        self.safety_engine = safety_engine
        self.db_mgr = db_mgr
        self.require_confirmation = require_confirmation
        self.default_min_age_hours = min_age_hours
        self._last_skipped_new = 0
        self._last_examined = 0

        self.disposable_roots = self._discover_disposable_roots()

    def _discover_disposable_roots(self):
        """
        Dynamically discovers and normalizes standard Windows temporary locations
        without hardcoding specific user names.
        """
        home = os.path.expanduser("~")
        local_app_data = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        sys_root = os.environ.get("SystemRoot", os.environ.get("WINDIR", "C:\\Windows"))

        candidate_roots = [
            tempfile.gettempdir(),
            os.environ.get("TEMP"),
            os.environ.get("TMP"),
            os.path.join(sys_root, "Temp"),
            os.path.join(local_app_data, "Temp"),
            os.path.join(local_app_data, "CrashDumps")
        ]

        seen_normalized = set()
        resolved_roots = []

        for cr in candidate_roots:
            if not cr:
                continue
            try:
                expanded = os.path.normpath(os.path.expandvars(cr))
                if os.path.exists(expanded) and os.path.isdir(expanded):
                    real_p = os.path.realpath(expanded)
                    lower_p = real_p.lower()
                    if lower_p not in seen_normalized:
                        seen_normalized.add(lower_p)
                        resolved_roots.append(expanded)
            except Exception as e:
                logger.debug(f"Error evaluating disposable root '{cr}': {e}")

        return resolved_roots

    def _classify_item(self, file_path):
        """Classifies a candidate into Temporary, Cache, Crash dumps, or Installers."""
        lower = file_path.lower()
        if lower.endswith(".dmp") or "crashdumps" in lower:
            return "Crash dumps"
        if lower.endswith(".msi") or (lower.endswith(".exe") and ("installer" in lower or "setup" in lower or "temp" in lower)):
            return "Installers"
        if "cache" in lower or lower.endswith(".chk"):
            return "Cache"
        return "Temporary"

    def _is_file_locked(self, file_path):
        """Checks non-intrusively whether a file is currently opened/locked by another process."""
        try:
            # Attempt to open exclusively or read without modifying
            with open(file_path, "rb"):
                pass
            return False
        except (PermissionError, OSError):
            return True

    def discover(self, min_age_hours=None):
        """
        Discovers safe cleanup candidates across allowed disposable roots.
        Applies strict age filtering (default > 24 hours) and safety checks.
        Returns a list of candidate dicts ready for removal.
        """
        age_hours = self.default_min_age_hours if min_age_hours is None else min_age_hours
        min_age_seconds = age_hours * 3600.0
        now = time.time()

        candidates = []
        files_examined = 0
        files_skipped_new = 0

        for root in self.disposable_roots:
            if not os.path.exists(root) or not os.path.isdir(root):
                continue

            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                if not self.safety_engine.validate_path(dirpath, self.disposable_roots):
                    continue

                for fname in filenames:
                    files_examined += 1
                    file_path = os.path.join(dirpath, fname)

                    if not self.safety_engine.validate_path(file_path, self.disposable_roots):
                        continue
                    if self.safety_engine.is_path_protected(file_path):
                        continue

                    try:
                        st = os.stat(file_path)
                        mtime = st.st_mtime
                        age_sec = now - mtime

                        if min_age_seconds > 0 and age_sec < min_age_seconds:
                            files_skipped_new += 1
                            continue

                        size = st.st_size
                        category = self._classify_item(file_path)
                        age_h = round(age_sec / 3600.0, 1)
                        age_days = round(age_h / 24.0, 1)
                        age_desc = f"{age_days}d old" if age_days >= 1.0 else f"{age_h}h old"

                        reason = f"Stale {category.lower()} (>24h)" if age_h >= 24.0 else f"Disposable {category.lower()}"

                        candidates.append({
                            "path": file_path,
                            "name": fname,
                            "size": size,
                            "size_mb": round(size / (1024 * 1024), 3),
                            "category": category,
                            "reason": reason,
                            "status": "SAFE TO CLEAN",
                            "is_dir": False,
                            "mtime": mtime,
                            "age_hours": age_h,
                            "age_display": age_desc,
                            "root_folder": root
                        })
                    except (PermissionError, OSError) as e:
                        logger.debug(f"Could not stat temporary file '{file_path}': {e}")
                        continue

        self._last_examined = files_examined
        self._last_skipped_new = files_skipped_new
        return candidates

    def discover_detailed(self, min_age_hours=None):
        """
        Discovers all files in disposable roots and categorizes them with detailed status indicators:
        - SAFE TO CLEAN
        - IN USE
        - TOO RECENT
        - PROTECTED
        - SKIPPED
        Used for rich interactive breakdown in the Junk & Temp Cleanup tab.
        """
        age_hours = self.default_min_age_hours if min_age_hours is None else min_age_hours
        min_age_seconds = age_hours * 3600.0
        now = time.time()

        all_items = []
        files_examined = 0
        files_skipped_new = 0

        for root in self.disposable_roots:
            if not os.path.exists(root) or not os.path.isdir(root):
                continue

            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                is_valid_dir = self.safety_engine.validate_path(dirpath, self.disposable_roots)

                for fname in filenames:
                    files_examined += 1
                    file_path = os.path.join(dirpath, fname)
                    category = self._classify_item(file_path)

                    if not is_valid_dir or not self.safety_engine.validate_path(file_path, self.disposable_roots):
                        all_items.append({
                            "path": file_path,
                            "name": fname,
                            "size": 0,
                            "size_mb": 0.0,
                            "category": category,
                            "reason": "Outside allowed disposable roots",
                            "status": "SKIPPED",
                            "is_dir": False,
                            "mtime": now,
                            "age_hours": 0.0,
                            "age_display": "0h",
                            "root_folder": root
                        })
                        continue

                    if self.safety_engine.is_path_protected(file_path):
                        all_items.append({
                            "path": file_path,
                            "name": fname,
                            "size": 0,
                            "size_mb": 0.0,
                            "category": category,
                            "reason": "Protected system path or file",
                            "status": "PROTECTED",
                            "is_dir": False,
                            "mtime": now,
                            "age_hours": 0.0,
                            "age_display": "0h",
                            "root_folder": root
                        })
                        continue

                    try:
                        st = os.stat(file_path)
                        mtime = st.st_mtime
                        age_sec = now - mtime
                        size = st.st_size
                        age_h = round(age_sec / 3600.0, 1)
                        age_days = round(age_h / 24.0, 1)
                        age_desc = f"{age_days}d old" if age_days >= 1.0 else f"{age_h}h old"

                        if min_age_seconds > 0 and age_sec < min_age_seconds:
                            files_skipped_new += 1
                            all_items.append({
                                "path": file_path,
                                "name": fname,
                                "size": size,
                                "size_mb": round(size / (1024 * 1024), 3),
                                "category": category,
                                "reason": f"Active recent file (<{age_hours}h old)",
                                "status": "TOO RECENT",
                                "is_dir": False,
                                "mtime": mtime,
                                "age_hours": age_h,
                                "age_display": age_desc,
                                "root_folder": root
                            })
                            continue

                        # Check if file is locked / in-use
                        if self._is_file_locked(file_path):
                            all_items.append({
                                "path": file_path,
                                "name": fname,
                                "size": size,
                                "size_mb": round(size / (1024 * 1024), 3),
                                "category": category,
                                "reason": "Currently opened / locked by an active process",
                                "status": "IN USE",
                                "is_dir": False,
                                "mtime": mtime,
                                "age_hours": age_h,
                                "age_display": age_desc,
                                "root_folder": root
                            })
                            continue

                        # File is stale and unlocked -> SAFE TO CLEAN
                        reason = f"Stale {category.lower()} (>24h)" if age_h >= 24.0 else f"Disposable {category.lower()}"
                        all_items.append({
                            "path": file_path,
                            "name": fname,
                            "size": size,
                            "size_mb": round(size / (1024 * 1024), 3),
                            "category": category,
                            "reason": reason,
                            "status": "SAFE TO CLEAN",
                            "is_dir": False,
                            "mtime": mtime,
                            "age_hours": age_h,
                            "age_display": age_desc,
                            "root_folder": root
                        })
                    except (PermissionError, OSError):
                        all_items.append({
                            "path": file_path,
                            "name": fname,
                            "size": 0,
                            "size_mb": 0.0,
                            "category": category,
                            "reason": "Locked or inaccessible",
                            "status": "IN USE",
                            "is_dir": False,
                            "mtime": now,
                            "age_hours": 0.0,
                            "age_display": "0h",
                            "root_folder": root
                        })

        self._last_examined = files_examined
        self._last_skipped_new = files_skipped_new
        return all_items

    def preview(self, min_age_hours=None):
        """
        SCAN ONLY mode.
        Returns itemized preview and summary metrics without performing any deletions.
        """
        candidates = self.discover(min_age_hours=min_age_hours)
        total_bytes = sum(c["size"] for c in candidates)
        categories_breakdown = {
            "Temporary": 0.0,
            "Cache": 0.0,
            "Crash dumps": 0.0,
            "Installers": 0.0
        }

        for c in candidates:
            cat = c["category"]
            categories_breakdown[cat] = categories_breakdown.get(cat, 0.0) + (c["size"] / (1024 * 1024))

        return {
            "count": len(candidates),
            "size_mb": round(total_bytes / (1024 * 1024), 2),
            "categories": {k: round(v, 2) for k, v in categories_breakdown.items()},
            "roots_scanned": list(self.disposable_roots),
            "candidates": candidates,
            "files_skipped_new": self._last_skipped_new,
            "files_examined": self._last_examined
        }

    def execute(self, candidates=None, batch_size=50, pause_between_batches=0.01, on_progress=None):
        """
        Executes cleanup on pre-approved candidate list in responsive batches.
        Safely handles locked/in-use files without force-terminating processes.
        Respects safety_engine dry_run mode and logs results to DB.
        """
        if candidates is None:
            candidates = self.discover()

        files_examined = len(candidates)
        files_removed = 0
        dirs_removed = 0
        bytes_recovered = 0
        files_skipped_in_use = 0
        errors = 0
        categories_recovered = {"Temporary": 0, "Cache": 0, "Crash dumps": 0, "Installers": 0}
        t0 = time.time()

        for idx, c in enumerate(candidates, 1):
            path = c["path"]
            size = c.get("size", 0)
            category = c.get("category", "Temporary")
            is_dir = c.get("is_dir", False)

            # Safety gate check
            allowed, reason = self.safety_engine.gate_action("cleanup_delete", path)
            if not allowed:
                if reason == "dry_run":
                    logger.debug(f"[DRY RUN / SAFE] Would remove: {path} | Category: {category} ({size} bytes)")
                    if not is_dir:
                        files_removed += 1
                    else:
                        dirs_removed += 1
                    bytes_recovered += size
                    categories_recovered[category] = categories_recovered.get(category, 0) + 1
            else:
                try:
                    if not is_dir and (os.path.isfile(path) or os.path.islink(path)):
                        os.unlink(path)
                        files_removed += 1
                        bytes_recovered += size
                        categories_recovered[category] = categories_recovered.get(category, 0) + 1
                    elif is_dir and os.path.isdir(path):
                        if not any(os.path.samefile(path, r) for r in self.disposable_roots if os.path.exists(r)):
                            shutil.rmtree(path)
                            dirs_removed += 1
                            bytes_recovered += size
                            categories_recovered[category] = categories_recovered.get(category, 0) + 1
                except (PermissionError, OSError) as e:
                    files_skipped_in_use += 1
                    logger.debug(f"Skipping locked/in-use temporary file: {path} ({e})")
                except Exception as e:
                    errors += 1
                    logger.warning(f"Error removing temporary item {path}: {e}")

            if on_progress:
                try:
                    on_progress(idx, len(candidates), path)
                except Exception:
                    pass

            if idx % batch_size == 0 and idx < len(candidates):
                time.sleep(pause_between_batches)

        dry_run = self.safety_engine.dry_run
        if not dry_run:
            dirs_removed += self._prune_empty_subdirs()

        space_mb = round(bytes_recovered / (1024 * 1024), 2)
        duration_sec = round(time.time() - t0, 2)

        if self.db_mgr:
            try:
                self.db_mgr.log_cleanup_event(
                    files_removed=files_removed,
                    dirs_removed=dirs_removed,
                    space_recovered_mb=space_mb,
                    categories=categories_recovered,
                    dry_run=dry_run,
                    files_examined=files_examined,
                    files_skipped_in_use=files_skipped_in_use,
                    files_skipped_new=self._last_skipped_new,
                    errors_count=errors,
                    duration_seconds=duration_sec
                )
            except Exception as e:
                logger.error(f"Failed to log cleanup event to database: {e}")

        result = {
            "files_examined": files_examined,
            "files_removed": files_removed,
            "files_deleted": files_removed,
            "dirs_removed": dirs_removed,
            "dirs_deleted": dirs_removed,
            "space_recovered_mb": space_mb,
            "files_skipped_in_use": files_skipped_in_use,
            "files_skipped_new": self._last_skipped_new,
            "errors": errors,
            "duration_seconds": duration_sec,
            "dry_run": dry_run,
            "categories_breakdown": categories_recovered,
            "roots_cleaned": list(self.disposable_roots)
        }
        logger.info(f"Cleanup execution finished: {result}")
        return result

    def _prune_empty_subdirs(self):
        """Safely removes empty subdirectories within disposable roots (skipping roots themselves)."""
        removed = 0
        for root in self.disposable_roots:
            if not os.path.exists(root) or not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, topdown=False):
                try:
                    if os.path.samefile(dirpath, root):
                        continue
                except Exception:
                    if os.path.normpath(dirpath).lower() == os.path.normpath(root).lower():
                        continue

                try:
                    if not os.listdir(dirpath):
                        allowed, _ = self.safety_engine.gate_action("cleanup_delete", dirpath)
                        if allowed:
                            os.rmdir(dirpath)
                            removed += 1
                except (PermissionError, OSError):
                    pass
        return removed
