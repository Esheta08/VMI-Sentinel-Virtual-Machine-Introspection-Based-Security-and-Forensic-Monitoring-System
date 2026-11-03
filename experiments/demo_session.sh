#!/usr/bin/env bash
# Guest-side demo (run INSIDE the VM): 8 min of normal activity, loud attack at 2 min.
set -u
nohup ~/normal_workload.sh 8 11 > /dev/null 2>&1 &
echo "Normal activity started (8 min). Attack in 2 minutes ..."
sleep 120
echo "ATTACK started  $(date -u +%T) UTC  (fast reconnaissance burst)"
~/attack_sim.sh fast
echo "ATTACK finished $(date -u +%T) UTC  -> watch the host terminal and the dashboard"
