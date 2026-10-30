#!/usr/bin/env bash
# Benign, human-paced workload for baseline collection inside the guest VM.
# Usage: ./normal_workload.sh <minutes> [seed]
# Logs every action with a UTC timestamp to ~/workload_normal.log (ground truth).
set -u
MIN=${1:-60}
SEED=${2:-42}
RANDOM=$SEED
LOG=~/workload_normal.log
END=$(( $(date +%s) + MIN * 60 ))

cmds=(
  "ls -la ~"
  "cat /etc/os-release"
  "df -h"
  "free -m"
  "uptime"
  "ps aux"
  "date"
  "grep -c processor /proc/cpuinfo"
  "find /usr/share/doc -maxdepth 1 -name 'p*'"
  "wc -l /etc/services"
  "python3 -c 'print(sum(range(1000)))'"
  "tar -czf /tmp/docs.tgz -C /usr/share/doc bash"
  "sha256sum /etc/hostname"
  "ip -br addr"
  "systemctl is-active cron"
)

echo "# normal start $(date -u +%FT%T.%3NZ) minutes=$MIN seed=$SEED" >> "$LOG"
while [ "$(date +%s)" -lt "$END" ]; do
  c=${cmds[$((RANDOM % ${#cmds[@]}))]}
  echo "$(date -u +%FT%T.%3NZ) $c" >> "$LOG"
  bash -c "$c" > /dev/null 2>&1
  sleep $(( 5 + RANDOM % 40 ))     # 5-44 s between actions, roughly human pace
done
echo "# normal end $(date -u +%FT%T.%3NZ)" >> "$LOG"
