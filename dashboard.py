"""
dashboard.py — SHFSL 2.0 PRODUCTION dashboard.

IMPORTANT: This dashboard watches whatever real directory is configured via
the SHFSL_MONITOR_ROOT environment variable. It is intended for an operator
running SHFSL against their own machine/server, and must NOT be the thing
exposed as the public Render demo (use demo_app.py for that — see README).

Run with: streamlit run dashboard.py
"""
import os
import sys
import time

import streamlit as st

from core.config import settings
from core.watcher import Watcher
from core.utils import load_log
from admin import send_alert_email

st.set_page_config(page_title="SHFSL 2.0 — Dashboard", page_icon="🛡️", layout="wide")

errors = settings.validate_for_production()
if settings.DEMO_MODE:
    st.warning(
        "SHFSL_DEMO_MODE is true — this dashboard is running in demo mode. "
        "Use demo_app.py for the public-safe sandbox demo instead.",
        icon="⚠️",
    )
if errors:
    st.error("Configuration error(s):\n\n" + "\n".join(f"- {e}" for e in errors))
    st.stop()

ROOT = os.path.abspath(settings.MONITOR_ROOT)
LOG_FILE = os.path.join(ROOT, "watcher_log.json")
DASH_LOG = os.path.join(ROOT, "activity_dashboard.log")

# Operators define their own registry via SHFSL_DECOY_FILES / SHFSL_SENSITIVE_FILES
# (comma-separated filenames), rather than a hardcoded list tied to one machine.
DECOY_FILES = [f.strip() for f in os.environ.get("SHFSL_DECOY_FILES", "").split(",") if f.strip()]
SENSITIVE_FILES = [f.strip() for f in os.environ.get("SHFSL_SENSITIVE_FILES", "").split(",") if f.strip()]
INITIAL_STATUSES = {f: "DECOY" for f in DECOY_FILES}
INITIAL_STATUSES.update({f: "SENSITIVE" for f in SENSITIVE_FILES})

if "watcher_started" not in st.session_state:
    watcher = Watcher(
        root_folder=ROOT,
        log_file=LOG_FILE,
        dashboard_log_file=DASH_LOG,
        initial_statuses=INITIAL_STATUSES,
        settings=settings,
        alert_fn=send_alert_email,
    )
    watcher.start(blocking=False)
    st.session_state.watcher_started = True
    st.session_state.watcher = watcher

st.title("🛡️ SHFSL 2.0 — Production Dashboard")
st.caption(f"Monitoring: `{ROOT}`  ·  Email alerts: {'enabled' if settings.email_enabled() else 'disabled'}")

log_data = load_log(LOG_FILE, INITIAL_STATUSES)
rows = [
    {
        "File": fn,
        "Status": d.get("status", "REAL"),
        "Last Event": d.get("last_event", "initialized"),
        "Risk Outcome": d.get("risk_outcome", "NONE"),
        "Risk Score": d.get("risk_score", 0),
        "Last Modified": d.get("last_modified", "N/A"),
    }
    for fn, d in log_data.items()
]
st.dataframe(rows, use_container_width=True, hide_index=True)

st.subheader("Activity log")
try:
    with open(DASH_LOG, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()[-100:]
except FileNotFoundError:
    lines = []
st.code("".join(reversed(lines)) if lines else "No events yet.", language=None)

time.sleep(2)
st.rerun()
