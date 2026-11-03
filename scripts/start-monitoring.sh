#!/usr/bin/env bash
# Run VMI-Sentinel on the host with ONE command:
#   collector (KVMI) -> PostgreSQL, live anomaly detector, web dashboard.
# Usage:   scripts/start-monitoring.sh [minutes=15]
# Needs:   the VM already running (scripts/start-vm.sh in another terminal).
# Shows:   live alerts in this terminal; dashboard at http://localhost:8501
# Stops:   by itself after [minutes], or press Ctrl+C (stops everything cleanly).
set -uo pipefail
MIN=${1:-15}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source .venv/bin/activate
LOG="logs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOG"

if [ -z "${VMI_DB_PASSWORD:-}" ]; then
  read -s -p 'DB password: ' VMI_DB_PASSWORD; echo; export VMI_DB_PASSWORD
fi
python -c "from database.database import get_connection; get_connection().close()" \
  2>/dev/null || { echo "Cannot connect to PostgreSQL with that password."; exit 1; }
sudo -v || exit 1
pgrep -f 'x86_64-softmmu/qemu-system-x86_64' > /dev/null \
  || { echo "The VM is not running. Start it first: scripts/start-vm.sh"; exit 1; }
if pgrep -x vmi_proc_monito > /dev/null; then
  echo "A collector is already running. Stop it first."; exit 1
fi

# Keep sudo credentials fresh for the clean shutdown at the end.
( while kill -0 $$ 2>/dev/null; do sudo -n -v 2>/dev/null; sleep 60; done ) &
KEEP=$!

# Background jobs of a script ignore Ctrl+C; the trap below stops them in order.
streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501 \
  --server.headless true > "$LOG/dashboard.log" 2>&1 &
DASH=$!
python -m detection.live_detector --vm vmi-guest --train-session 2 > "$LOG/alerts.log" 2>&1 &
LIVE=$!
sudo rm -f /tmp/kvmi.sock
( sudo timeout -s INT "${MIN}m" ./collector/native/vmi_proc_monitor vmi-guest /tmp/kvmi.sock 0x1fbc0 \
    2> "$LOG/monitor.err" \
  | tee -i "$LOG/events.jsonl" \
  | python -m collector.kvmi_process_adapter > "$LOG/adapter.log" 2>&1 ) &
PIPE=$!

STOPPING=0
finish() {
  [ "$STOPPING" = 1 ] && return
  STOPPING=1
  echo
  echo "[run] stopping collector..."
  sudo pkill -INT -x vmi_proc_monito 2>/dev/null
  wait "$PIPE" 2>/dev/null
  echo "[run] scoring the last windows..."
  sleep 12
  kill "$LIVE" "$DASH" "$KEEP" 2>/dev/null
  wait 2>/dev/null
  echo "================ summary ================"
  tail -n 1 "$LOG/monitor.err"
  tail -n 1 "$LOG/adapter.log"
  echo "alerts raised: $(grep -c '^\[ALERT\]' "$LOG/alerts.log")"
  echo "logs: $LOG/"
  exit 0
}
trap finish INT TERM

echo "============================================================"
echo " VMI-Sentinel running for ${MIN} min   (Ctrl+C to stop early)"
echo " Dashboard:  http://localhost:8501"
echo " Logs:       $LOG/"
echo " In the VM, run:  ~/demo.sh"
echo "============================================================"
tail -n +1 -f "$LOG/alerts.log" --pid="$PIPE" &
TAIL=$!
wait "$TAIL" 2>/dev/null
finish
