#!/bin/bash
# Hold-back copy cost: read/write copy vs copy_file_range/FICLONE (holdback_fast_copy). Detection disabled by a huge threshold.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
t() { local s=$(date +%s.%N); "$@" >/dev/null 2>&1; echo "scale=3; ($(date +%s.%N) - $s)/1" | bc; }
med() { printf '%s\n' "$@" | sort -n | sed -n 3p; }
bench() { local d=$1 b=() c=() e=() g=()
  for r in 1 2 3 4 5; do
    rm -rf $d/w; mkdir -p $d/w
    dd if=/dev/urandom of=$d/w/big bs=128k count=1024 2>/dev/null; sleep 0.3          # 128 MB original (hold-back limit is 64 MB, so use 48 MB below)
    rm -f $d/w/big; dd if=/dev/urandom of=$d/w/big bs=128k count=384 2>/dev/null; sleep 0.3
    b+=($(t dd if=/dev/urandom of=$d/w/big bs=4k count=1 conv=notrunc))                # small edit of a 48 MB file: cost is the pending copy
    for i in $(seq 1 100); do head -c 1000000 /dev/urandom > $d/w/m$i; done; sleep 0.3
    mk() { for i in $(seq 1 100); do echo x | dd of=$d/w/m$i bs=1 count=1 conv=notrunc 2>/dev/null; done; }; c+=($(t mk))   # 100 x 1 MB files touched once
    ow() { for i in $(seq 1 1000); do echo hello > $d/w/s$i; done; }; for i in $(seq 1 1000); do echo hi > $d/w/s$i; done; sleep 0.3; e+=($(t ow))
  done
  echo "$(med ${b[@]}) $(med ${c[@]}) $(med ${e[@]})"
}
mkdir -p $WORK/direct; D=$(bench $WORK/direct)
start_mount OF1 '$a promote_threshold = 100000000\nsuspend_on_detect = false\nbaseline_interval_seconds = 0' || exit 1; H=$(bench $M); stop_mount
start_mount OF2 '$a promote_threshold = 100000000\nsuspend_on_detect = false\nbaseline_interval_seconds = 0\nholdback_fast_copy = true' || exit 1; F=$(bench $M); stop_mount
echo "seconds (median of 5): 4KiB edit of a 48MB file | touch 100 x 1MB files | overwrite 1000 small files"
echo "direct             : $D"; echo "hold-back read/write: $H"; echo "hold-back fast copy : $F"
