#!/usr/bin/env bash
# BENIGN emulation of post-compromise behaviour inside the guest VM, used to test
# the detector. It only runs read-only recon commands and a throwaway script in
# /tmp: nothing is downloaded, no privileges are escalated, nothing is modified
# outside /tmp.
#
# Usage: ./attack_sim.sh fast   # rapid recon burst (easy case: seconds long)
#        ./attack_sim.sh slow   # same commands spread over ~2 min (harder case)
# Logs start/end with UTC timestamps to ~/workload_attack.log (ground truth).
set -u
MODE=${1:-fast}
LOG=~/workload_attack.log

recon() {
  id; whoami; uname -a; hostname; cat /etc/passwd; ls -la /tmp; ps -ef
  ss -tulpn 2>/dev/null; ip route
}

dropped_script() {
  cat > /tmp/.x.sh <<'EOF'
#!/bin/sh
for f in /etc/*.conf; do head -n 1 "$f"; done
EOF
  chmod +x /tmp/.x.sh
  /tmp/.x.sh
  rm -f /tmp/.x.sh
}

echo "# attack $MODE start $(date -u +%FT%T.%3NZ)" >> "$LOG"
if [ "$MODE" = "fast" ]; then
  for i in $(seq 1 30); do recon; done > /dev/null 2>&1
  for i in $(seq 1 10); do dropped_script; done > /dev/null 2>&1
else
  for i in $(seq 1 12); do
    recon > /dev/null 2>&1
    dropped_script > /dev/null 2>&1
    sleep 10
  done
fi
echo "# attack $MODE end $(date -u +%FT%T.%3NZ)" >> "$LOG"
