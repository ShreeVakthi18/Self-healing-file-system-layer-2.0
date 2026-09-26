"""
tests/test_core.py — SHFSL 2.0 test suite.

All tests operate exclusively inside pytest's `tmp_path` fixture. Nothing
here ever touches a real user directory, and no test relies on network,
email, or an external watchdog Observer thread's exact timing more than
necessary (a small sleep is used where filesystem events must propagate).
"""
import json
import os
import time

import pytest

from core.config import Settings
from core.logic import DetectionEngine
from core.snapshots import SnapshotEngine
from core.utils import load_log, save_log, is_path_inside_root, is_unsafe_symlink


@pytest.fixture
def sandbox(tmp_path):
    root = tmp_path / "sandbox"
    root.mkdir()
    return root


@pytest.fixture
def test_settings():
    s = Settings()
    s.DEMO_MODE = True
    s.MAX_SNAPSHOTS_PER_FILE = 5
    s.SNAPSHOT_RETENTION_DAYS = 30
    s.MAX_SNAPSHOT_STORAGE_MB = 50
    s.MAX_LOG_LINES = 50
    s.RAPID_DELETE_THRESHOLD = 3
    s.RAPID_DELETE_WINDOW_SECONDS = 5
    return s


def make_engine(root, settings, alert_fn=None):
    log_file = str(root / "watcher_log.json")
    dash_log = str(root / "activity_dashboard.log")
    return DetectionEngine(str(root), log_file, dash_log, settings, alert_fn=alert_fn)


# ── Path safety ──────────────────────────────────────────────────────────

def test_path_inside_root_accepts_child(sandbox):
    child = sandbox / "a.txt"
    child.write_text("x")
    assert is_path_inside_root(str(child), str(sandbox))


def test_path_inside_root_rejects_escape(sandbox, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    assert not is_path_inside_root(str(outside), str(sandbox))


def test_symlink_escape_is_detected(sandbox, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    link = sandbox / "link.txt"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")
    assert is_unsafe_symlink(str(link), str(sandbox))


# ── Log I/O ──────────────────────────────────────────────────────────────

def test_load_log_initializes_new_files(sandbox):
    log_file = str(sandbox / "watcher_log.json")
    data = load_log(log_file, {"decoy.txt": "DECOY"})
    assert data["decoy.txt"]["status"] == "DECOY"
    assert data["decoy.txt"]["risk_score"] == 0


def test_load_log_recovers_from_corrupted_json(sandbox):
    log_file = str(sandbox / "watcher_log.json")
    with open(log_file, "w") as f:
        f.write("{not valid json")
    data = load_log(log_file, {"a.txt": "REAL"})
    assert data["a.txt"]["status"] == "REAL"
    backups = [f for f in os.listdir(sandbox) if "corrupted" in f]
    assert backups, "corrupted log should be backed up, not silently discarded"


def test_status_correction_preserves_risk_score(sandbox):
    log_file = str(sandbox / "watcher_log.json")
    data = load_log(log_file, {"f.txt": "REAL"})
    data["f.txt"]["risk_score"] = 42
    data["f.txt"]["status"] = "WRONG"
    save_log(log_file, data)
    (sandbox / "f.txt").write_text("hi")
    data2 = load_log(log_file, {"f.txt": "SENSITIVE"})
    assert data2["f.txt"]["status"] == "SENSITIVE"
    assert data2["f.txt"]["risk_score"] == 42


# ── Snapshot + rollback ──────────────────────────────────────────────────

def test_snapshot_created_and_pruned(sandbox, test_settings):
    engine = SnapshotEngine(str(sandbox), max_snapshots_per_file=3, retention_days=30, max_storage_mb=50)
    f = sandbox / "doc.txt"
    for i in range(6):
        f.write_text(f"version {i}")
        engine.create_snapshot(str(f), is_rolling_back=False)
        time.sleep(0.02)
    time.sleep(0.3)  # allow async prune thread to finish
    storage_dir = sandbox / "snapshot_storage"
    snaps = [p for p in storage_dir.glob("doc.txt.*") if p.is_file()]
    assert 0 < len(snaps) <= 3


def test_rollback_restores_clean_content(sandbox):
    engine = SnapshotEngine(str(sandbox), max_snapshots_per_file=5, retention_days=30, max_storage_mb=50)
    f = sandbox / "decoy.txt"
    f.write_text("clean original")
    engine.create_snapshot(str(f), is_rolling_back=False)
    time.sleep(0.1)

    f.write_text("TAMPERED CONTENT")
    flag = {"rolling": False}
    result = engine.rollback_file(str(f), lambda v: flag.__setitem__("rolling", v))

    assert result["success"], result.get("error")
    assert f.read_text() == "clean original"
    assert flag["rolling"] is False  # flag always released


def test_rollback_missing_snapshot_reports_error(sandbox):
    engine = SnapshotEngine(str(sandbox), max_snapshots_per_file=5, retention_days=30, max_storage_mb=50)
    f = sandbox / "never_snapshotted.txt"
    f.write_text("data")
    result = engine.rollback_file(str(f), lambda v: None)
    assert not result["success"]
    assert result["error"] in ("no_snapshot_dir", "no_snapshots")


def test_snapshot_refuses_path_outside_root(sandbox, tmp_path):
    engine = SnapshotEngine(str(sandbox), max_snapshots_per_file=5, retention_days=30, max_storage_mb=50)
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    assert engine.create_snapshot(str(outside), is_rolling_back=False) is None


# ── Detection engine: decoy / sensitive / ransomware ──────────────────────

def test_decoy_tamper_triggers_rollback(sandbox, test_settings):
    alerts = []
    engine = make_engine(sandbox, test_settings, alert_fn=lambda s, b: alerts.append(s))
    f = sandbox / "decoy.docx"
    f.write_text("original decoy content")

    engine.process_event("modified", str(f), {"decoy.docx": "DECOY"})
    time.sleep(0.05)
    f.write_text("HACKED")
    outcome = engine.process_event("modified", str(f), {"decoy.docx": "DECOY"})

    assert outcome == "HIGH_DECOY_ALERT"
    assert any("Decoy" in a for a in alerts)


def test_sensitive_deletion_no_auto_rollback(sandbox, test_settings):
    alerts = []
    engine = make_engine(sandbox, test_settings, alert_fn=lambda s, b: alerts.append(s))
    f = sandbox / "contract.docx"
    f.write_text("sensitive data")
    engine.process_event("created", str(f), {"contract.docx": "SENSITIVE"})

    os.remove(f)
    outcome = engine.process_event("deleted", str(f), {"contract.docx": "SENSITIVE"})

    assert outcome == "HIGH_SENSITIVE_DELETION"
    assert not f.exists()  # confirmed: NOT auto-restored
    assert any("Sensitive" in a for a in alerts)


def test_ransomware_rename_triggers_rollback(sandbox, test_settings):
    engine = make_engine(sandbox, test_settings)
    f = sandbox / "plan.docx"
    f.write_text("clean plan")
    engine.process_event("created", str(f), {"plan.docx": "REAL"})
    time.sleep(0.05)

    locked = sandbox / "plan.docx.lock"
    os.rename(f, locked)
    outcome = engine.process_event("modified", str(locked), {"plan.docx": "REAL"})

    assert outcome == "HIGH_RANSOMWARE_ROLLBACK"


def test_duplicate_events_are_debounced(sandbox, test_settings):
    engine = make_engine(sandbox, test_settings)
    f = sandbox / "normal.txt"
    f.write_text("v1")
    r1 = engine.process_event("modified", str(f), {"normal.txt": "REAL"})
    r2 = engine.process_event("modified", str(f), {"normal.txt": "REAL"})  # immediate duplicate
    assert r1 == "LOW_NORMAL_ACTIVITY"
    assert r2 is None  # deduped, not double-counted


def test_rapid_deletion_pattern_detected(sandbox, test_settings):
    alerts = []
    engine = make_engine(sandbox, test_settings, alert_fn=lambda s, b: alerts.append(s))
    for i in range(4):
        f = sandbox / f"file{i}.txt"
        f.write_text("x")
        engine.process_event("created", str(f), {})
        time.sleep(0.02)
        os.remove(f)
        engine.process_event("deleted", str(f), {})
    assert any("mass deletion" in a.lower() or "rapid" in a.lower() for a in alerts)


def test_normal_activity_is_low_risk(sandbox, test_settings):
    engine = make_engine(sandbox, test_settings)
    f = sandbox / "notes.txt"
    f.write_text("hello")
    outcome = engine.process_event("created", str(f), {"notes.txt": "REAL"})
    assert outcome == "LOW_NORMAL_ACTIVITY"


# ── Config validation ─────────────────────────────────────────────────────

def test_production_requires_monitor_root():
    s = Settings()
    s.DEMO_MODE = False
    s.MONITOR_ROOT = ""
    errors = s.validate_for_production()
    assert errors


def test_production_rejects_dangerous_root():
    s = Settings()
    s.DEMO_MODE = False
    s.MONITOR_ROOT = "/etc"
    errors = s.validate_for_production()
    assert errors


def test_demo_mode_skips_validation():
    s = Settings()
    s.DEMO_MODE = True
    s.MONITOR_ROOT = ""
    assert s.validate_for_production() == []


def test_email_disabled_in_demo_mode():
    s = Settings()
    s.DEMO_MODE = True
    s.SENDER_EMAIL = "a@b.com"
    s.SENDER_PASSWORD = "x"
    s.RECEIVER_EMAIL = "c@d.com"
    assert s.email_enabled() is False
