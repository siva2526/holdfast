#!/bin/bash
# Full evaluation reported in the paper. Resumable: a step is skipped if its .ok marker exists, so the script can be re-run after an
# interruption. Needs a built ../build and a working FUSE mount. Takes many hours on 2 vCPUs, so run it as a background job.
# Output: results/final (override with OUT=...). Set PYTHONHASHSEED=0 (done below) so that attack parameters are reproducible.
cd "$(dirname "$0")"; OUT=${OUT:-$PWD/results/final}; mkdir -p "$OUT"; export PYTHONHASHSEED=0
step() { n=$1; shift; [ -f "$OUT/$n.ok" ] && return; "$@" && touch "$OUT/$n.ok"; }
# 1. attack matrix: 19 attacks x 2 corpora x 6 trials, four presets
for cfg in holdfast prov restore_only redirect_only; do
  step attack_$cfg python3 hf_attack.py "$OUT/attack_$cfg.csv" --configs $cfg --corpora mixed,unknown --trials 6 --jobs 3
done
# 2. benign suites S1-S4 (110 workloads, 3 repetitions) per preset
for cfg in holdfast restore_only redirect_only prov; do
  step s1_$cfg python3 hf_benign.py  "$OUT/s1_$cfg.csv" --configs $cfg --reps 3 --jobs 2
  step s2_$cfg python3 hf_benign2.py "$OUT/s2_$cfg.csv" --suite s2 --configs $cfg --reps 3 --jobs 2
  step s3_$cfg python3 hf_benign2.py "$OUT/s3_$cfg.csv" --suite s3 --configs $cfg --reps 3 --jobs 2
  step s4_$cfg python3 hf_benign4.py "$OUT/s4_$cfg.csv" --configs $cfg --reps 3 --jobs 2
done
# 3. adversarial suite S5, adaptive-attacker search, release/crash test, paced attackers vs the rate bound
step s5 python3 hf_benign5.py "$OUT/s5.csv" --configs holdfast,prov --reps 3 --jobs 2
step adaptive python3 hf_adaptive.py "$OUT/adaptive.csv" --configs holdfast,restore_only,redirect_only --corpora mixed,unknown --n 40 --jobs 3
step release bash -c "python3 hf_release_test.py > '$OUT/release.json'"
step bound python3 hf_bound.py "$OUT/bound.csv"
# 4. recovery that does not depend on detection (blind recover), and the ring-window variant
mkdir -p results/blind
step blind python3 hf_blind.py results/blind/blind.csv
step ringwindow python3 hf_ringwindow.py results/blind/ringwindow.csv
echo ALLDONE > "$OUT/DONE"
