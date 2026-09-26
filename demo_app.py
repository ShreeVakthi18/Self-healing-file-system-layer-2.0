"""
demo_app.py — SHFSL 2.0 PUBLIC SAFE DEMO.

What this is:
  A real instance of the SHFSL detection/snapshot/rollback engine
  (core/*.py — the SAME code path used in "production" mode), pointed at
  an isolated, auto-generated sandbox directory created fresh per browser
  session under the container's own temp folder.

What this is NOT:
  - It never touches any path outside its own sandbox.
  - It never reads SHFSL_MONITOR_ROOT or any real filesystem location.
  - Email alerting is force-disabled (core.config.settings.DEMO_MODE gate).
  - Nothing here can affect the host machine, other sessions, or any real
    user data — each visitor gets their own throwaway sandbox that is
    deleted when they hit "Reset demo" or the session ends.

This file is the ONLY thing that should be deployed as the public Render
service. It deliberately does not expose the production dashboard.py,
which is designed to watch an operator-configured real directory and is
not safe to expose to anonymous internet traffic.
"""
import os
import shutil
import tempfile
import time
import uuid

import streamlit as st

from core.watcher import Watcher
from core.utils import load_log, save_log
from core.config import settings

st.set_page_config(page_title="SHFSL 2.0 — Live Demo", page_icon="🛡️", layout="wide")

DEMO_FILES = {
    "CEO_Contract.docx": ("DECOY", "This is a decoy honeypot file. Any change to it is a trap trigger."),
    "API_Keys_Internal.json": ("DECOY", '{"note": "decoy honeypot — not a real key"}'),
    "Legal_Settlement_Docs.docx": ("SENSITIVE", "Sample sensitive document — deletion is not auto-restored."),
    "Q4_Budget_Forecast.xlsx": ("SENSITIVE", "Sample sensitive spreadsheet placeholder."),
    "meeting_notes.txt": ("REAL", "Ordinary file. Normal edits are logged as low-risk."),
}


def new_sandbox():
    old = st.session_state.get("sandbox_dir")
    if old and os.path.isdir(old):
        try:
            shutil.rmtree(old, ignore_errors=True)
        except OSError:
            pass
    sandbox = os.path.join(tempfile.gettempdir(), "shfsl_demo", uuid.uuid4().hex[:12])
    os.makedirs(sandbox, exist_ok=True)
    for filename, (_, content) in DEMO_FILES.items():
        with open(os.path.join(sandbox, filename), "w", encoding="utf-8") as f:
            f.write(content)

    log_file = os.path.join(sandbox, "watcher_log.json")
    dash_log = os.path.join(sandbox, "activity_dashboard.log")
    initial_statuses = {name: status for name, (status, _) in DEMO_FILES.items()}
    load_log(log_file, initial_statuses)
    open(dash_log, "a").close()

    watcher = Watcher(
        root_folder=sandbox,
        log_file=log_file,
        dashboard_log_file=dash_log,
        initial_statuses=initial_statuses,
        settings=settings,
        alert_fn=lambda subject, body: None,  # demo mode: email always disabled
    )
    observer = watcher.start(blocking=False)

    st.session_state.sandbox_dir = sandbox
    st.session_state.log_file = log_file
    st.session_state.dash_log = dash_log
    st.session_state.initial_statuses = initial_statuses
    st.session_state.watcher = watcher
    st.session_state.observer = observer


if "sandbox_dir" not in st.session_state or not os.path.isdir(st.session_state.get("sandbox_dir", "")):
    new_sandbox()

sandbox = st.session_state.sandbox_dir


def act(action_label, fn):
    fn()
    st.toast(action_label)
    time.sleep(0.6)  # let the watcher thread process the fs event
    st.rerun()


st.title("🛡️ SHFSL 2.0 — Live Detection Demo")
st.caption(
    "Sandboxed demo instance. This page monitors an isolated, auto-generated "
    "temporary directory only — never your device or any real files. "
    f"Sandbox id: `{os.path.basename(sandbox)}`"
)

st.info(
    "This is a **safe, isolated demo**. It runs the real SHFSL detection and "
    "rollback engine against disposable sample files created just for your session. "
    "It does not monitor, access, or affect any real computer or production system.",
    icon="ℹ️",
)

col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("🎯 Tamper decoy file", width='stretch'):
        act("Decoy tampered — watch for automatic rollback",
            lambda: open(os.path.join(sandbox, "CEO_Contract.docx"), "a").write("\nTAMPERED"))

with col2:
    if st.button("🗑️ Delete sensitive file", width='stretch'):
        act("Sensitive file deleted — no auto-rollback, alert raised",
            lambda: os.remove(os.path.join(sandbox, "Legal_Settlement_Docs.docx"))
            if os.path.exists(os.path.join(sandbox, "Legal_Settlement_Docs.docx")) else None)

with col3:
    if st.button("🦠 Simulate ransomware rename", width='stretch'):
        def _ransom():
            src = os.path.join(sandbox, "meeting_notes.txt")
            if os.path.exists(src):
                os.rename(src, src + ".locked")
        act("Ransomware-style rename triggered — watch for automatic rollback", _ransom)

with col4:
    if st.button("🔄 Reset demo", width='stretch'):
        watcher = st.session_state.get("watcher")
        if watcher:
            watcher.stop()
        new_sandbox()
        st.rerun()

st.divider()

# ── Live state ───────────────────────────────────────────────────────────
log_data = load_log(st.session_state.log_file, st.session_state.initial_statuses)

st.subheader("Monitored files")
rows = []
for filename, details in log_data.items():
    rows.append({
        "File": filename,
        "Status": details.get("status", "REAL"),
        "Last Event": details.get("last_event", "initialized"),
        "Risk Outcome": details.get("risk_outcome", "NONE"),
        "Risk Score": details.get("risk_score", 0),
    })
st.dataframe(rows, width='stretch', hide_index=True)

st.subheader("Activity log")
try:
    with open(st.session_state.dash_log, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()[-30:]
except FileNotFoundError:
    lines = []

if lines:
    st.code("".join(reversed(lines)), language=None)
else:
    st.caption("No security events yet — try one of the buttons above.")

st.divider()
st.caption(
    "Source: this demo runs `core/watcher.py`, `core/logic.py`, and "
    "`core/snapshots.py` unmodified — the same engine described in the README. "
    "It is intentionally restricted to a disposable sandbox for public safety."
)
