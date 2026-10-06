#!/usr/bin/env bash
# Rough GPU vs CPU throughput for EAR cracking (PBKDF2-HMAC-SHA1, 18000 iters).
# Uses a not-found digit mask so it exhausts a known candidate count.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release >/dev/null 2>&1
BIN=target/release/fm-vangogh
F=tests/fixtures/ear_password.fmp12

run() { # label, count, args...
  local label=$1 count=$2; shift 2
  local start end secs rate
  start=$(date +%s.%N)
  "$BIN" crack "$F" "$@" >/dev/null 2>&1 || true
  end=$(date +%s.%N)
  secs=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.2f", b-a}')
  rate=$(awk -v c="$count" -v s="$secs" 'BEGIN{printf "%d", c/s}')
  printf "%-28s %10s cand  %8ss  ~%s/s\n" "$label" "$count" "$secs" "$rate"
}

echo "fm-vangogh benchmark ($(date -u +%Y-%m-%dT%H:%MZ))"
"$BIN" devices
echo
run "GPU digits len6 (1e6)"   1000000 --mask --charset digits --min 6 --max 6 --gpu
run "CPU digits len5 (1e5)"    100000 --mask --charset digits --min 5 --max 5
