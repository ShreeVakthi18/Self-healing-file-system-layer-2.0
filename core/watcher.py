"""
core/watcher.py — SHFSL 2.0 hardened watchdog wrapper.

Fixes vs. original prototype:
  - Ignores/guards against symlinked paths that escape the monitored root.
  - on_moved, on_deleted, on_created, on_modified all consistently check
    is_rolling_back (original only guarded some handlers).
  - Graceful shutdown via observer.stop()/join() on SIGINT/SIGTERM.
  - No hardcoded IGNORE_FILES tied to a specific dev machine — ignore list
    is derived from the package's own module filenames + common noise.
"""
import os
import signal
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .logic import DetectionEngine
from .utils import is_path_inside_root

IGNORE_FOLDERS = {"__pycache__", "snapshot_storage", "snapshots", ".git", "staging"}
IGNORE_SUFFIXES = (".tmp", ".temp", ".swp", ".part", ".lnk", ".db-journal", ".pyc")
IGNORE_PREFIXES = ("~wrl", "~$", ".~", "~", ".")


class Watcher:
    def __init__(self, root_folder, log_file, dashboard_log_file, initial_statuses,
                 settings, alert_fn=None, self_paths=None):
        self.root_folder = os.path.abspath(root_folder)
        self.initial_statuses = initial_statuses
        self.engine = DetectionEngine(self.root_folder, log_file, dashboard_log_file, settings, alert_fn)
        self.self_paths = {os.path.basename(p) for p in (self_paths or [])} | {
            os.path.basename(log_file), os.path.basename(dashboard_log_file),
        }
        self._observer = None

    def _should_ignore(self, filepath):
        filename = os.path.basename(filepath)
        fn_lower = filename.lower()
        if any(fn_lower.startswith(p) for p in IGNORE_PREFIXES):
            return True
        if any(fn_lower.endswith(s) for s in IGNORE_SUFFIXES):
            return True
        if filename in self.self_paths:
            return True
        if any(folder in filepath.split(os.sep) for folder in IGNORE_FOLDERS):
            return True
        if not is_path_inside_root(filepath, self.root_folder):
            return True
        return False

    def _make_handler(self):
        watcher = self

        class Handler(FileSystemEventHandler):
            def dispatch(self, event):
                if watcher.engine.is_rolling_back:
                    return
                super().dispatch(event)

            def on_created(self, event):
                if not event.is_directory and not watcher._should_ignore(event.src_path):
                    watcher.engine.process_event("created", event.src_path, watcher.initial_statuses)

            def on_deleted(self, event):
                if not event.is_directory and not watcher._should_ignore(event.src_path):
                    watcher.engine.process_event("deleted", event.src_path, watcher.initial_statuses)

            def on_modified(self, event):
                if not event.is_directory and not watcher._should_ignore(event.src_path):
                    watcher.engine.process_event("modified", event.src_path, watcher.initial_statuses)

            def on_moved(self, event):
                if event.is_directory:
                    return
                if not watcher._should_ignore(event.src_path):
                    watcher.engine.process_event("deleted", event.src_path, watcher.initial_statuses)
                time.sleep(0.05)
                if not watcher.engine.is_rolling_back and not watcher._should_ignore(event.dest_path):
                    watcher.engine.process_event("created", event.dest_path, watcher.initial_statuses)

        return Handler()

    def start(self, blocking=True):
        from .utils import load_log
        load_log(self.engine.log_file, self.initial_statuses)

        self._observer = Observer()
        self._observer.schedule(self._make_handler(), self.root_folder, recursive=True)
        self._observer.start()

        if not blocking:
            return self._observer

        def _shutdown(signum, frame):
            self.stop()

        try:
            signal.signal(signal.SIGTERM, _shutdown)
            signal.signal(signal.SIGINT, _shutdown)
        except (ValueError, OSError):
            pass  # not in main thread — caller manages lifecycle

        try:
            while self._observer.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
