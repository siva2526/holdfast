#!/bin/bash
# Overhead: direct vs rrfs without hold-back vs rrfs with hold-back (detection disabled by a huge threshold).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
which bc >/dev/null || { echo need bc; exit 1; }
t() { local s=$(date +%s.%N); "$@" >/dev/null 2>&1; echo "scale=3; ($(date +%s.%N) - $s)/1" | bc; }
med() { printf '%s\n' "$@" | sort -n | sed -n 2p; }
bench() { # $1 dir  -> prints 4 numbers: newfile64MB, overwrite32MB, create1000, overwrite1000
  local d=$1 a=() b=() c=() e=()
  for r in 1 2 3; do
    rm -rf $d/w; mkdir -p $d/w
    a+=($(t dd if=/dev/zero of=$d/w/new bs=128k count=512 conv=notrunc))
    dd if=/dev/zero of=$d/w/big bs=128k count=256 2>/dev/null; sleep 0.3
    b+=($(t dd if=/dev/urandom of=$d/w/big bs=128k count=256 conv=notrunc))
    mk() { for i in $(seq 1 1000); do echo hi > $d/w/s$i; done; }; c+=($(t mk)); sleep 0.3
    ow() { for i in $(seq 1 1000); do echo hello > $d/w/s$i; done; }; e+=($(t ow))
  done
  echo "$(med ${a[@]}) $(med ${b[@]}) $(med ${c[@]}) $(med ${e[@]})"
}
mkdir -p $WORK/direct; D=$(bench $WORK/direct)
start_mount OH1 '$a promote_threshold = 100000000\nholdback_enabled = false\nsuspend_on_detect = false\nbaseline_interval_seconds = 0' || exit 1; N=$(bench $M); stop_mount
start_mount OH2 '$a promote_threshold = 100000000\nsuspend_on_detect = false\nbaseline_interval_seconds = 0' || exit 1; H=$(bench $M); stop_mount
echo "seconds (median of 3): new-64MB | overwrite-32MB-in-place | create-1000-files | overwrite-1000-small-files"
echo "direct        : $D"; echo "rrfs no-hold  : $N"; echo "rrfs hold-back: $H"
