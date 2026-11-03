"""
VMI-Sentinel dashboard.

  streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501

Run from the project root with the venv active and VMI_DB_PASSWORD exported.
It binds to localhost only; view it from another machine through an SSH tunnel:
  ssh -L 8501:127.0.0.1:8501 geu@<lab-pc-ip>   then open http://localhost:8501
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # project root on the path

import streamlit as st

from dashboard import data
from detection.compare_detectors import session_features
from detection.live_detector import fit_detectors

st.set_page_config(page_title="VMI-Sentinel", page_icon="🛡️", layout="wide")


@st.cache_resource(show_spinner="Fitting detectors on the training session…")
def get_detectors(vm: str, train_session: int):
    return fit_detectors(session_features(vm, train_session, 30))


st.sidebar.title("🛡️ VMI-Sentinel")
vm = st.sidebar.text_input("Virtual machine", "vmi-guest")
train_session = int(st.sidebar.number_input("Training session (normal baseline)", 1, value=2))

sessions = data.sessions_frame(vm)
if sessions.empty:
    st.warning(f"No monitoring sessions recorded for {vm}.")
    st.stop()

session_ids = list(sessions.index)[::-1]          # newest first


def label(i):
    row = sessions.loc[i]
    state = "stopped" if row["stopped"] else "RUNNING"
    start = data.to_local(sessions.loc[[i]], ["start"])["start"].iloc[0]
    return f"Session {i} · {start:%d %b %H:%M} · {state}"


session = st.sidebar.selectbox("Monitoring session", session_ids, format_func=label)
row = sessions.loc[session]
auto = st.sidebar.checkbox("Auto-refresh every 10 s", value=not row["stopped"])
st.sidebar.caption("Times shown in IST. Alerts come from detection/live_detector.py; "
                   "scores above 0 mean the detector would alert.")

start, end = data.session_range(row)
detectors = get_detectors(vm, train_session)
windows = data.window_scores(vm, start, end, detectors)
alerts = data.alerts_frame(vm, start, end)
counts = data.event_counts(vm, start, end)

st.title(f"VM {vm} — session {session}")
st.caption("Process activity observed from outside the VM via KVMI/LibVMI "
           "(no agent inside the guest).")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Duration", f"{(end - start).total_seconds() / 60:.1f} min")
c2.metric("30 s windows", len(windows))
c3.metric("Events", int(counts["count"].sum()) if not counts.empty else 0)
c4.metric("Alerts", len(alerts))

if windows.empty:
    st.info("No complete 30 s window yet.")
else:
    local = data.to_local(windows, ["index"])
    st.subheader("Process activity per 30 s window")
    st.line_chart(local[["process_created_count", "process_exec_count",
                         "process_terminated_count"]])
    st.subheader("Anomaly scores (above 0 = alert)")
    score_cols = [c for c in local.columns if c.endswith("_score")]
    st.line_chart(local[score_cols])

st.subheader("Alerts (forensic context: programs that ran in the window)")
if alerts.empty:
    st.success("No alerts stored for this session.")
else:
    st.dataframe(data.to_local(alerts, ["window_start"]), width="stretch",
                 hide_index=True)

left, right = st.columns([1, 2])
with left:
    st.subheader("Event types")
    st.dataframe(counts, width="stretch", hide_index=True)
with right:
    st.subheader("Latest process events")
    st.dataframe(data.to_local(data.recent_events(vm, start, end, 200), ["timestamp"]),
                 width="stretch", hide_index=True, height=300)

if auto:
    time.sleep(10)
    st.rerun()
