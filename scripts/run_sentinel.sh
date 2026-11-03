#!/usr/bin/env bash
# VMI-Sentinel: start the whole host-side pipeline with ONE command.
#   collector (KVMI/LibVMI) -> adapter -> PostgreSQL -> live detector -> alerts
#   + dashboard at http://localhost:8501
# Usage:  ./scripts/run_sentinel.sh [minutes]     (default 15; Ctrl+C stops earlier)
# Needs:  the VM running (./scripts/start_vm.sh in another terminal).
set -u
MIN=${1:-15}
VM=vmi-guest
TRAIN_SESSION=2
CURRENT_TASK_OFFSET=0x1fbc0

cd "$(dirname "$0")/.." || exit 1
source .venv/bin/activate || { echo "Python venv (.venv) not found"; exit 1; }

# ---- checks --------------------------------------------------------------
pgrep -f '[q]emu-system-x86_64.*guest.qcow2' > /dev/null \
  || { echo "The VM is not running. Start it first:  ./scripts/start_vm.sh"; exit 1; }
# Match the collector invocation itself, not editors/viewers of vmi_proc_monitor.c
pgrep -f "[v]mi_proc_monitor $VM " > /dev/null \
  && { echo "A collector is already running. Stop it first."; exit 1; }
python -c 'import streamlit' 2> /dev/null \
  || { echo "Streamlit missing. Install once:  pip install streamlit"; exit 1; }
if [ -z "${VMI_DB_PASSWORD:-}" ]; then
  read -r -s -p 'Database password: ' VMI_DB_PASSWORD; echo; export VMI_DB_PASSWORD
fi
PGPASSWORD="$VMI_DB_PASSWORD" psql -h 127.0.0.1 -U vmi_app -d vmi_sentinel -tAc 'SELECT 1' \
  > /dev/null 2>&1 || { echo "Database login failed (wrong password?)"; exit 1; }
echo "sudo is needed for the collector:"
sudo -v || exit 1

# ---- start components ----------------------------------------------------
LOG=logs/$(date +%Y%m%d-%H%M%S)
mkdir -p "$LOG"

streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501 \
  --server.headless true > "$LOG/dashboard.log" 2>&1 &
DASH=$!

python -m detection.live_detector --vm "$VM" --train-session "$TRAIN_SESSION" \
  > "$LOG/alerts.log" 2> "$LOG/live.log" &
LIVE=$!

# Start the collector and wait until it has really attached to the VM.
# LibVMI only waits a short time for QEMU to connect, so retry a few times.
start_collector() {
  sudo rm -f /tmp/kvmi.sock
  ( sudo timeout -s INT "${MIN}m" ./collector/native/vmi_proc_monitor "$VM" /tmp/kvmi.sock \
        "$CURRENT_TASK_OFFSET" 2> "$LOG/monitor.err" \
      | tee -i -a "$LOG/events.jsonl" \
      | python -m collector.kvmi_process_adapter > /dev/null 2>> "$LOG/adapter.log" ) &
  PIPE=$!
  for _ in $(seq 1 60); do
    grep -q '^\[monitor\] listening' "$LOG/monitor.err" 2> /dev/null && return 0
    kill -0 "$PIPE" 2> /dev/null || return 1        # collector exited (e.g. init failed)
    sleep 1
  done
  return 1
}

attached=0
for attempt in 1 2 3; do
  echo "Attaching to the VM (attempt $attempt/3) ..."
  if start_collector; then attached=1; break; fi
  cp "$LOG/monitor.err" "$LOG/monitor-attempt$attempt.err" 2> /dev/null
  sudo pkill -INT -f "[v]mi_proc_monitor $VM " 2> /dev/null
  wait "$PIPE" 2> /dev/null
  sleep 3
done
if [ "$attached" -ne 1 ]; then
  echo "ERROR: the collector could not attach to the VM after 3 attempts."
  echo "       Last collector messages:"; tail -n 4 "$LOG/monitor.err" | sed 's/^/         /'
  echo "       Try restarting the VM (sudo poweroff inside it, then ./scripts/start_vm.sh)."
  kill "$LIVE" "$DASH" 2> /dev/null; wait "$LIVE" "$DASH" 2> /dev/null
  exit 1
fi

stop_all() {
  trap - INT TERM
  echo
  echo "Stopping the collector ..."
  # [v] keeps this command line from matching itself
  sudo pkill -INT -f "[v]mi_proc_monitor $VM " 2> /dev/null
  for _ in $(seq 1 20); do kill -0 "$PIPE" 2> /dev/null || break; sleep 1; done
  if kill -0 "$PIPE" 2> /dev/null; then
    echo "Collector did not stop within 20 s; forcing it (session will have no stop marker)."
    sudo pkill -TERM -f "[v]mi_proc_monitor $VM " 2> /dev/null
  fi
  wait "$PIPE" 2> /dev/null
  echo "Letting the live detector score the last windows (15 s) ..."
  sleep 15
  kill "$LIVE" 2> /dev/null; wait "$LIVE" 2> /dev/null
  echo "Collector summary: $(tail -n 1 "$LOG/monitor.err" 2> /dev/null)"
  echo "Alerts this run:   $(grep -c '^\[ALERT\]' "$LOG/alerts.log" 2> /dev/null || true)"
  read -r -p "Dashboard still open at http://localhost:8501 - press Enter to close it. " _
  kill "$DASH" 2> /dev/null; wait "$DASH" 2> /dev/null
  echo "Done. Logs: $LOG"
  exit 0
}
trap stop_all INT TERM

cat <<INFO
=====================================================================
 VMI-Sentinel is running (stops by itself after $MIN min; Ctrl+C = stop now)
 Dashboard : http://localhost:8501   -> pick the RUNNING session
 Logs      : $LOG
 Alerts appear below, about 40-75 s after suspicious activity:
=====================================================================
INFO
tail -n +1 -f --pid="$PIPE" "$LOG/alerts.log"
stop_all
