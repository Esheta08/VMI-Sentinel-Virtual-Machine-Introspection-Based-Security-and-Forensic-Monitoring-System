#!/usr/bin/env bash
# Guest-side overhead benchmark (run INSIDE the VM).
#   ./bench.sh off      # with NO monitor attached
#   ./bench.sh on       # while VMI-Sentinel is monitoring
# Appends rows to ~/bench_results.csv: label,test,rep,seconds,utc
# Tests are interleaved per repetition so slow drift affects all tests alike.
set -u
LABEL=${1:?usage: ./bench.sh <off|on> [reps]}
REPS=${2:-5}
OUT=~/bench_results.csv
[ -f "$OUT" ] || echo "label,test,rep,seconds,utc" > "$OUT"

spawn() { for _ in $(seq 1 300); do /bin/true; done; }
cpu()   { python3 -c 'sum(i * i for i in range(5_000_000))'; }
io()    { tar -czf /tmp/bench.tgz -C /usr/share/doc . 2> /dev/null; rm -f /tmp/bench.tgz; }

timeit() {   # timeit <test-name>  -> prints seconds
  local start=$EPOCHREALTIME
  "$1" > /dev/null 2>&1
  awk -v s="$start" -v e="$EPOCHREALTIME" 'BEGIN { printf "%.4f", e - s }'
}

echo "benchmark '$LABEL': $REPS repetitions of spawn, cpu, io"
for rep in $(seq 1 "$REPS"); do
  for test in spawn cpu io; do
    secs=$(timeit "$test")
    echo "$LABEL,$test,$rep,$secs,$(date -u +%FT%TZ)" >> "$OUT"
    printf '  rep %d  %-5s %8.3f s\n' "$rep" "$test" "$secs"
  done
done
echo "done -> $OUT"
