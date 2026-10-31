#!/usr/bin/env bash
# Start ONE test session inside the guest: normal workload + scheduled attacks.
# - Refuses to start if a session is already running (lock file + process check).
# - Archives old logs so ground truth starts clean.
# - Prints exactly what is running, so a failed start is noticed immediately.
#
# Usage: ./run_session.sh [minutes] [seed]
# Schedule (seconds after start):
#   120  stealth attack (~5 min, one command every 30 s)
#   480  fast attack
#   then 300 s pause, then slow attack
set -u
MIN=${1:-20}
SEED=${2:-7}
LOCK=/tmp/vmi_session.lock

exec 9> "$LOCK"
if ! flock -n 9; then
  echo "REFUSED: a session is already running (lock held)"; exit 1
fi
# Scripts run as "bash /path/normal_workload.sh ...": match that exact command-line
# shape (anchored), so unrelated shells that merely mention the names never match.
PATTERN='^bash [^ ]*/(normal_workload|attack_sim)\.sh'
if pgrep -f "$PATTERN" > /dev/null; then
  echo "REFUSED: a workload or attack is still running"; exit 1
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
for f in ~/workload_normal.log ~/workload_attack.log; do
  [ -f "$f" ] && mv "$f" "$f.$stamp.bak"
done

# Background jobs inherit fd 9, so the lock stays held until they all finish.
nohup setsid ~/normal_workload.sh "$MIN" "$SEED" > /dev/null 2>&1 &
nohup setsid bash -c '
  sleep 120; ~/attack_sim.sh stealth
  sleep $(( 480 - 120 - 300 > 0 ? 480 - 120 - 300 : 0 )); ~/attack_sim.sh fast
  sleep 300; ~/attack_sim.sh slow' > /dev/null 2>&1 &

sleep 2
echo "--- running now ---"
pgrep -af "$PATTERN"
pgrep -af 'sleep 120; ~/attack_sim.sh stealth' | grep -v pgrep
echo "--- normal log ---"
head -n 1 ~/workload_normal.log
echo "STARTED $(date -u +%FT%TZ): ${MIN} min workload (seed ${SEED}); stealth @2m, fast @~8m, slow @~13m"
