"""
core/logic.py — SHFSL 2.0 hardened detection & response engine.

Fixes applied vs. the original prototype:
  - Duplicate-event de-duplication: watchdog on some platforms (esp. via
    OneDrive/network shares) fires multiple events for one logical change.
    A short per-file debounce window collapses these before they reach the
    alerting/rollback path.
  - Rapid-deletion pattern (mass-delete ransomware behavior) is now
    actually detected, not just individual sensitive-file deletions.
  - Email alerting is a no-op (safely) whenever config says it's disabled
    (demo mode, or missing credentials) — never raises, never blocks.
"""
import os
import threading
import time
from collections import deque
from datetime import datetime

from .utils import load_log, save_log, update_risk_score, append_dashboard_log
from .snapshots import SnapshotEngine, RANSOMWARE_EXTENSIONS


class DetectionEngine:
    def __init__(self, root_folder, log_file, dashboard_log_file, settings,
                 alert_fn=None, debounce_seconds=0.4):
        self.root_folder = root_folder
        self.log_file = log_file
        self.dashboard_log_file = dashboard_log_file
        self.settings = settings
        self.alert_fn = alert_fn or (lambda subject, body: None)
        self.debounce_seconds = debounce_seconds

        self.snapshots = SnapshotEngine(
            root_folder,
            snapshot_dirname=settings.SNAPSHOT_DIRNAME,
            max_snapshots_per_file=settings.MAX_SNAPSHOTS_PER_FILE,
            retention_days=settings.SNAPSHOT_RETENTION_DAYS,
            max_storage_mb=settings.MAX_SNAPSHOT_STORAGE_MB,
        )

        self.is_rolling_back = False
        self._roll_lock = threading.Lock()
        self._last_event = {}  # filename -> (event_type, monotonic_time)
        self._delete_times = deque()  # rapid-delete tracking (all files)
        self._dash_lock = threading.Lock()

    def _set_rolling_back(self, value):
        with self._roll_lock:
            self.is_rolling_back = value

    def _is_duplicate(self, filename, event_type):
        now = time.monotonic()
        last = self._last_event.get(filename)
        self._last_event[filename] = (event_type, now)
        if last and last[0] == event_type and (now - last[1]) < self.debounce_seconds:
            return True
        return False

    def _record_deletion_and_check_rapid(self):
        now = time.monotonic()
        self._delete_times.append(now)
        window = self.settings.RAPID_DELETE_WINDOW_SECONDS
        while self._delete_times and now - self._delete_times[0] > window:
            self._delete_times.popleft()
        return len(self._delete_times) >= self.settings.RAPID_DELETE_THRESHOLD

    def _dash_log(self, message):
        append_dashboard_log(self.dashboard_log_file, message, self.settings.MAX_LOG_LINES, self._dash_lock)

    def process_event(self, event_type, filepath, initial_statuses):
        if self.is_rolling_back:
            return None

        filepath = os.path.abspath(filepath)
        filename = os.path.basename(filepath)

        if self._is_duplicate(filename, event_type):
            return None

        log_data = load_log(self.log_file, initial_statuses)
        file_status = self._resolve_status(filename, log_data, initial_statuses)
        risk_outcome = self._assess(event_type, filepath, filename, file_status, log_data)

        last_modified = "DELETED"
        if os.path.exists(filepath):
            try:
                last_modified = time.ctime(os.path.getmtime(filepath))
            except OSError:
                last_modified = "DELETED"

        log_data = load_log(self.log_file, initial_statuses)
        new_score = update_risk_score(log_data, filename, risk_outcome)
        entry = log_data.get(filename, {})
        entry.update({
            "last_modified": last_modified,
            "status": file_status,
            "event": event_type,
            "risk_outcome": risk_outcome,
            "last_event": event_type,
        })
        log_data[filename] = entry
        save_log(self.log_file, log_data)
        return risk_outcome

    @staticmethod
    def _resolve_status(filename, log_data, initial_statuses):
        existing = log_data.get(filename, {}).get("status")
        if existing in ("DECOY", "SENSITIVE"):
            return existing
        if filename in initial_statuses:
            return initial_statuses[filename]
        return "REAL"

    def _assess(self, event_type, filepath, filename, file_status, log_data):
        if event_type in ("modified", "created") and not self.is_rolling_back:
            self.snapshots.create_snapshot(filepath, self.is_rolling_back)

        # Rapid mass-deletion — independent of individual file classification
        if event_type == "deleted" and self._record_deletion_and_check_rapid():
            self.alert_fn(
                "CRITICAL: Rapid mass deletion detected",
                f"{self.settings.RAPID_DELETE_THRESHOLD}+ files deleted within "
                f"{self.settings.RAPID_DELETE_WINDOW_SECONDS}s. Possible ransomware sweep.",
            )
            self._dash_log(
                f"CRITICAL: RAPID DELETION PATTERN detected (threshold "
                f"{self.settings.RAPID_DELETE_THRESHOLD}/{self.settings.RAPID_DELETE_WINDOW_SECONDS}s)."
            )

        if file_status == "DECOY" and event_type in ("modified", "deleted"):
            self.alert_fn(
                f"CRITICAL: Decoy Honeypot Tampered — {filename}",
                f"File: {filename}\nEvent: {event_type.upper()}\nAction: Automatic rollback triggered.\n"
                f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            )
            result = self.snapshots.rollback_file(filepath, self._set_rolling_back)
            if result["success"]:
                self._dash_log(f"CRITICAL: DECOY TAMPERING on '{filename}'. "
                                f"Restored from '{result['snapshot_used']}'. AUTOMATIC ROLLBACK SUCCESSFUL.")
            else:
                self._dash_log(f"CRITICAL: DECOY TAMPERING on '{filename}'. "
                                f"ROLLBACK FAILED — {result.get('error')}. Manual restore required.")
            return "HIGH_DECOY_ALERT"

        if file_status == "SENSITIVE" and event_type == "deleted":
            self.alert_fn(
                f"CRITICAL: Sensitive File Deleted — {filename}",
                f"File: {filename}\nEvent: DELETED\nAction: No automatic rollback — human review required.\n"
                f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            )
            self._dash_log(f"CRITICAL: SENSITIVE FILE DELETED — '{filename}'. "
                            f"HIGH_SENSITIVE_DELETION. Immediate administrator review required. No auto-rollback.")
            return "HIGH_SENSITIVE_DELETION"

        if (event_type in ("created", "modified") and not self.is_rolling_back
                and any(filename.lower().endswith(ext) or (ext + ".") in filename.lower()
                        for ext in RANSOMWARE_EXTENSIONS)):
            original = self.snapshots.derive_original_filename(filename)
            if (log_data.get(filename, {}).get("risk_outcome") == "HIGH_RANSOMWARE_ROLLBACK"
                    or log_data.get(original, {}).get("risk_outcome") == "HIGH_RANSOMWARE_ROLLBACK"):
                return "HIGH_RANSOMWARE_ROLLBACK"

            alert_level = file_status if file_status in ("SENSITIVE", "DECOY") else "REAL"
            self.alert_fn(
                f"CRITICAL: Ransomware Pattern — {alert_level} file — {filename}",
                f"File: {filename}\nFile Type: {alert_level}\nEvent: {event_type.upper()}\n"
                f"Action: Automatic rollback triggered.\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            )
            result = self.snapshots.rollback_file(filepath, self._set_rolling_back)
            if result["success"]:
                self._dash_log(
                    f"CRITICAL: RANSOMWARE PATTERN on '{filename}' ({alert_level}). "
                    f"Restored as '{result.get('restored_as', filename)}' from "
                    f"'{result['snapshot_used']}'. AUTOMATIC ROLLBACK SUCCESSFUL."
                )
            else:
                self._dash_log(
                    f"CRITICAL: RANSOMWARE PATTERN on '{filename}' ({alert_level}). "
                    f"ROLLBACK FAILED — {result.get('error')}. Manual restore required."
                )
            return "HIGH_RANSOMWARE_ROLLBACK"

        return "LOW_NORMAL_ACTIVITY"
