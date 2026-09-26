"""
core/utils.py — SHFSL 2.0 hardened utilities.

Fixes applied vs. the original prototype:
  - Path traversal / symlink-escape guard (is_path_inside_root).
  - Symlinks are never followed for snapshot/rollback operations.
  - Atomic, lock-protected JSON log read/write (temp file + os.replace).
  - Corrupted JSON is backed up, never silently discarded without a trace.
  - risk_score is always preserved across status corrections.
"""
import json
import os
import shutil
import threading
from datetime import datetime

_log_lock = threading.RLock()


def is_path_inside_root(path, root):
    """
    True only if `path` resolves (symlinks included) to a location
    inside `root`. Used to reject path-traversal / symlink-escape attempts
    before any file operation (snapshot, rollback, delete) touches disk.
    """
    try:
        real_root = os.path.realpath(root)
        real_path = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    return os.path.commonpath([real_root, real_path]) == real_root


def is_unsafe_symlink(path, root):
    """True if `path` is a symlink pointing outside of `root`."""
    if not os.path.islink(path):
        return False
    return not is_path_inside_root(path, root)


def atomic_write_json(path, data):
    """Write JSON atomically: temp file + fsync + os.replace."""
    tmp_path = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        return True
    except Exception as e:
        print(f"[UTILS] Failed to write {path}: {e}")
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        return False


def load_log(log_file, initial_statuses):
    """
    Loads the file-event log, seeding any newly-registered files.
    Corrupted JSON is backed up (not lost) and the log restarts clean.
    """
    with _log_lock:
        log_data = {}
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read().strip()
                if content:
                    log_data = json.loads(content)
            except json.JSONDecodeError:
                backup_path = f"{log_file}.corrupted_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                try:
                    shutil.copy2(log_file, backup_path)
                    print(f"[UTILS] Corrupted log backed up to {backup_path}")
                except OSError:
                    pass
                log_data = {}

        changed = False
        root = os.path.dirname(log_file) or "."
        for filename, initial_status in initial_statuses.items():
            if filename not in log_data or "status" not in log_data[filename]:
                log_data[filename] = {
                    "last_modified": "N/A",
                    "initialized_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": initial_status,
                    "event": "initialized",
                    "risk_outcome": "NONE",
                    "last_event": "initialized",
                    "risk_score": 0,
                }
                changed = True
            elif (
                os.path.exists(os.path.join(root, filename))
                and log_data[filename].get("status") != initial_status
            ):
                log_data[filename]["status"] = initial_status
                log_data[filename]["last_event"] = "status_corrected"
                changed = True

        if changed:
            atomic_write_json(log_file, log_data)

        return log_data


def save_log(log_file, log_data):
    with _log_lock:
        return atomic_write_json(log_file, log_data)


def update_risk_score(log_data, filename, new_outcome):
    """Accumulate a bounded [0, 100] risk score in-memory."""
    risk_weights = {
        "HIGH_RANSOMWARE_ROLLBACK": 100,
        "HIGH_DECOY_ALERT": 90,
        "HIGH_SENSITIVE_DELETION": 75,
        "LOW_NORMAL_ACTIVITY": 5,
        "NONE": 0,
    }
    entry = log_data.get(filename, {})
    current = entry.get("risk_score", 0)
    new_score = min(current + risk_weights.get(new_outcome, 0), 100)
    if filename in log_data:
        log_data[filename]["risk_score"] = new_score
    return new_score


def append_dashboard_log(log_path, message, max_lines, lock):
    """Thread-safe, bounded, atomic append to the human-readable activity log."""
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    entry = f"{timestamp} {message}\n"
    with lock:
        try:
            lines = []
            if os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            if len(lines) >= max_lines:
                lines = lines[-(max_lines - 1):]
            lines.append(entry)
            tmp_path = f"{log_path}.tmp.{os.getpid()}"
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, log_path)
        except Exception as e:
            print(f"[UTILS] Failed to write dashboard log: {e}")
