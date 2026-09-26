"""
core/snapshots.py — SHFSL 2.0 hardened snapshot & rollback engine.

Fixes applied vs. the original prototype:
  - Path-traversal / symlink-escape guard before any read/write.
  - Snapshot pruning is bounded by count, AGE, and TOTAL STORAGE SIZE
    (the original only bounded by count -> unbounded disk growth over time).
  - Snapshot writes use a temp-file + os.replace pattern (no half-written
    snapshots ever get picked up by rollback).
  - Rollback retry loop uses bounded, capped backoff instead of long fixed
    sleeps, and always releases the rolling-back flag in `finally`.
  - `_derive_original_filename` unchanged in spirit but defensively bounded.
"""
import os
import shutil
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path

from .utils import is_path_inside_root, is_unsafe_symlink

RANSOMWARE_EXTENSIONS = [".lock", ".encrypted", ".ransom", ".crypted", ".crypt", ".enc", ".locked"]

SKIP_PREFIXES = ("~", ".~", "~$")
SKIP_SUFFIXES = (".tmp", ".temp", ".~tmp", ".swp", ".part", ".lock", ".lnk")


class SnapshotEngine:
    def __init__(self, root_folder, snapshot_dirname="snapshot_storage",
                 max_snapshots_per_file=10, retention_days=30, max_storage_mb=200):
        self.root_folder = os.path.abspath(root_folder)
        self.snapshot_storage = os.path.join(self.root_folder, snapshot_dirname)
        self.max_snapshots_per_file = max_snapshots_per_file
        self.retention_days = retention_days
        self.max_storage_bytes = max_storage_mb * 1024 * 1024
        os.makedirs(self.snapshot_storage, exist_ok=True)
        self._prune_lock = threading.Lock()

    # ── Pruning ──────────────────────────────────────────────────────────
    def _prune_old_snapshots(self, file_storage_dir, base_filename):
        """
        Bounded by count, age, and total on-disk size for this file's
        snapshot family. Runs synchronously but is cheap; called from a
        background thread by create_snapshot() so it never blocks the
        watcher's event loop.
        """
        with self._prune_lock:
            path = Path(file_storage_dir)
            snapshots = sorted(path.glob(f"{base_filename}*"), key=lambda p: p.name, reverse=True)

            cutoff = datetime.now() - timedelta(days=self.retention_days)
            keep, drop = [], []
            for snap in snapshots:
                try:
                    mtime = datetime.fromtimestamp(snap.stat().st_mtime)
                except OSError:
                    drop.append(snap)
                    continue
                if len(keep) < self.max_snapshots_per_file and mtime >= cutoff:
                    keep.append(snap)
                else:
                    drop.append(snap)

            # Enforce total storage cap across the whole snapshot_storage dir.
            total_size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
            if total_size > self.max_storage_bytes:
                # Drop oldest kept snapshots for this file first until under cap
                for snap in sorted(keep, key=lambda p: p.stat().st_mtime):
                    if total_size <= self.max_storage_bytes:
                        break
                    try:
                        total_size -= snap.stat().st_size
                        drop.append(snap)
                        keep.remove(snap)
                    except OSError:
                        pass

            for old in drop:
                try:
                    old.unlink()
                except OSError:
                    pass

    def prune_async(self, file_storage_dir, base_filename):
        t = threading.Thread(
            target=self._prune_old_snapshots,
            args=(file_storage_dir, base_filename),
            daemon=True,
        )
        t.start()

    # ── Snapshot creation ────────────────────────────────────────────────
    def create_snapshot(self, filepath, is_rolling_back):
        if is_rolling_back:
            return None
        if not is_path_inside_root(filepath, self.root_folder):
            print(f"[SNAPSHOT] Refused: '{filepath}' resolves outside monitored root.")
            return None
        if is_unsafe_symlink(filepath, self.root_folder):
            print(f"[SNAPSHOT] Refused: '{filepath}' is a symlink escaping the monitored root.")
            return None
        if not os.path.exists(filepath) or os.path.isdir(filepath):
            return None

        filename = os.path.basename(filepath)
        if (any(filename.startswith(p) for p in SKIP_PREFIXES)
                or any(filename.lower().endswith(s) for s in SKIP_SUFFIXES)):
            return None

        relative_path = os.path.relpath(filepath, self.root_folder)
        file_storage_dir = os.path.join(self.snapshot_storage, os.path.dirname(relative_path))
        os.makedirs(file_storage_dir, exist_ok=True)

        base, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        snapshot_name = f"{base}{ext}.{timestamp}"
        dest_tmp = os.path.join(file_storage_dir, f".{snapshot_name}.tmp")
        dest_final = os.path.join(file_storage_dir, snapshot_name)

        try:
            shutil.copy2(filepath, dest_tmp)
            os.replace(dest_tmp, dest_final)  # atomic — rollback never sees a partial file
            self.prune_async(file_storage_dir, f"{base}{ext}")
            return dest_final
        except Exception as e:
            print(f"[SNAPSHOT] Failed to snapshot {filepath}: {e}")
            try:
                if os.path.exists(dest_tmp):
                    os.remove(dest_tmp)
            except OSError:
                pass
            return None

    # ── Rollback ─────────────────────────────────────────────────────────
    @staticmethod
    def derive_original_filename(filename):
        fn_lower = filename.lower()
        for rext in RANSOMWARE_EXTENSIONS:
            if (rext + ".") in fn_lower:
                idx = fn_lower.index(rext)
                return filename[:idx] + filename[idx + len(rext):]
            if fn_lower.endswith(rext):
                return filename[: -len(rext)]
        return filename

    def rollback_file(self, filepath, is_rolling_back_setter):
        """
        Restores the latest clean snapshot. is_rolling_back_setter is a
        callable(bool) used to toggle the caller's is_rolling_back flag,
        always released in `finally` regardless of outcome.
        """
        result = {"success": False, "snapshot_used": None, "error": None}

        if not is_path_inside_root(filepath, self.root_folder):
            result["error"] = "path_outside_root"
            return result

        filename = os.path.basename(filepath)
        original_filename = self.derive_original_filename(filename)
        restore_target = os.path.join(os.path.dirname(filepath), original_filename)

        relative_dir = os.path.relpath(os.path.dirname(filepath), self.root_folder)
        file_storage_dir = os.path.join(self.snapshot_storage, relative_dir)

        if not os.path.exists(file_storage_dir):
            result["error"] = "no_snapshot_dir"
            return result

        search_dir = Path(file_storage_dir)
        candidates = sorted(
            [f for f in search_dir.glob("*")
             if f.name.lower().startswith(original_filename.lower() + ".")
             and not f.name.startswith(".")],
            key=lambda p: p.name,
            reverse=True,
        )
        if not candidates:
            result["error"] = "no_snapshots"
            return result

        latest = candidates[0]
        is_rolling_back_setter(True)
        success = False
        try:
            for attempt in range(1, 6):
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    break
                except PermissionError:
                    time.sleep(min(0.5 * attempt, 2))
            else:
                raise PermissionError(f"Could not remove {filepath} after retries")

            if os.path.normcase(restore_target) != os.path.normcase(filepath):
                if os.path.exists(restore_target):
                    try:
                        os.remove(restore_target)
                    except OSError:
                        pass

            for attempt in range(1, 6):
                try:
                    shutil.copy2(str(latest), restore_target)
                    break
                except PermissionError:
                    time.sleep(min(0.5 * attempt, 2))
            else:
                raise PermissionError(f"Could not restore to {restore_target} after retries")

            result["success"] = True
            result["snapshot_used"] = latest.name
            result["restored_as"] = original_filename
            success = True
            return result
        except Exception as e:
            result["error"] = str(e)
            return result
        finally:
            time.sleep(0.5 if success else 1.0)
            is_rolling_back_setter(False)
