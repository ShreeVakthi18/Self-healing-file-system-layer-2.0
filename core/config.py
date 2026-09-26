"""
core/config.py — SHFSL 2.0 centralized configuration.

All secrets and environment-dependent values are read from environment
variables (optionally loaded from a local .env file via python-dotenv).
NOTHING sensitive is hardcoded here or anywhere else in the codebase.
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()  # no-op if .env doesn't exist; never raises
except ImportError:
    pass


def _bool_env(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _int_env(name, default):
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


class Settings:
    # --- App mode ---
    # DEMO_MODE=true is the ONLY mode allowed for the public deployment.
    # It forces monitoring to be confined to an isolated, auto-generated
    # sandbox directory and disables outbound email entirely.
    DEMO_MODE = _bool_env("SHFSL_DEMO_MODE", default=True)
    DEBUG = _bool_env("SHFSL_DEBUG", default=False)

    # --- Filesystem root ---
    # In production (non-demo) mode this MUST be set explicitly and is
    # validated at startup (must exist, must be a directory, must not be
    # a root/system path). It is never taken from a web request.
    MONITOR_ROOT = os.environ.get("SHFSL_MONITOR_ROOT", "").strip()

    # --- Snapshots ---
    SNAPSHOT_DIRNAME = os.environ.get("SHFSL_SNAPSHOT_DIR", "snapshot_storage")
    MAX_SNAPSHOTS_PER_FILE = _int_env("SHFSL_MAX_SNAPSHOTS_PER_FILE", 10)
    SNAPSHOT_RETENTION_DAYS = _int_env("SHFSL_SNAPSHOT_RETENTION_DAYS", 30)
    MAX_SNAPSHOT_STORAGE_MB = _int_env("SHFSL_MAX_SNAPSHOT_STORAGE_MB", 200)

    # --- Logging ---
    MAX_LOG_LINES = _int_env("SHFSL_MAX_LOG_LINES", 500)
    LOG_LEVEL = os.environ.get("SHFSL_LOG_LEVEL", "INFO")

    # --- Email alerting (disabled entirely in demo mode) ---
    SENDER_EMAIL = os.environ.get("SHFSL_SENDER_EMAIL", "")
    RECEIVER_EMAIL = os.environ.get("SHFSL_RECEIVER_EMAIL", "")
    SENDER_PASSWORD = os.environ.get("SHFSL_SENDER_PASSWORD", "")
    SMTP_SERVER = os.environ.get("SHFSL_SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = _int_env("SHFSL_SMTP_PORT", 587)

    # --- Web server ---
    PORT = _int_env("PORT", 8501)  # Render injects PORT
    HOST = "0.0.0.0"

    # --- Rapid-deletion / anti-ransomware thresholds ---
    RAPID_DELETE_THRESHOLD = _int_env("SHFSL_RAPID_DELETE_THRESHOLD", 5)
    RAPID_DELETE_WINDOW_SECONDS = _int_env("SHFSL_RAPID_DELETE_WINDOW_SECONDS", 10)

    def email_enabled(self):
        # Instance method (not classmethod): must see per-instance overrides,
        # e.g. in tests that construct a Settings() and flip DEMO_MODE off.
        if self.DEMO_MODE:
            return False
        return bool(self.SENDER_EMAIL and self.SENDER_PASSWORD and self.RECEIVER_EMAIL)

    def validate_for_production(self):
        """
        Returns a list of clear, actionable error strings if production
        (non-demo) mode is misconfigured. Called at startup — fail fast
        rather than silently monitoring the wrong thing or leaking secrets.
        """
        errors = []
        if self.DEMO_MODE:
            return errors  # demo mode has its own self-contained setup

        if not self.MONITOR_ROOT:
            errors.append("SHFSL_MONITOR_ROOT must be set when SHFSL_DEMO_MODE=false.")
        else:
            root = os.path.abspath(self.MONITOR_ROOT)
            if not os.path.isdir(root):
                errors.append(f"SHFSL_MONITOR_ROOT '{root}' does not exist or is not a directory.")
            # Refuse obviously dangerous roots
            dangerous = {os.path.abspath(os.sep), "/", "/etc", "/root", "/home", "C:\\", "C:\\Windows"}
            if root in dangerous:
                errors.append(f"SHFSL_MONITOR_ROOT '{root}' is a system-level path and is refused for safety.")

        return errors


settings = Settings()
