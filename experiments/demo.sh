#!/usr/bin/env bash
# Guest-side demo: normal activity for 10 min, a fast recon attack after DELAY s.
# Usage (inside the VM): ~/demo.sh [delay_seconds=120]
set -u
DELAY=${1:-120}
exec 9> /tmp/vmi_session.lock
flock -n 9 || { echo "REFUSED: a session is already running"; exit 1; }
rm -f ~/workload_attack.log
nohup setsid ~/normal_workload.sh 10 11 > /dev/null 2>&1 &
echo "normal activity started (10 min). attack in ${DELAY} s..."
sleep "$DELAY"
echo ">>> ATTACK starting  $(date -u +%T) UTC"
~/attack_sim.sh fast
echo ">>> ATTACK finished  $(date -u +%T) UTC  -> watch the host: alert within ~1 min"
