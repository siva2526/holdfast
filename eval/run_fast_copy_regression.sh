#!/bin/bash
# Regression of the opt-in holdback_fast_copy path: same attack matrix and benign suites as the final evaluation, preset 'fast'.
cd "$(dirname "$0")"; OUT=$PWD/results/fast; mkdir -p $OUT; export PYTHONHASHSEED=0
step() { n=$1; shift; [ -f $OUT/$n.ok ] && return; "$@" && touch $OUT/$n.ok; }
step attack python3 hf_attack.py $OUT/attack_fast.csv --configs fast --corpora mixed,unknown --trials 6 --jobs 3
step s1 python3 hf_benign.py  $OUT/s1_fast.csv --configs fast --reps 3 --jobs 2
step s2 python3 hf_benign2.py $OUT/s2_fast.csv --suite s2 --configs fast --reps 3 --jobs 2
step s3 python3 hf_benign2.py $OUT/s3_fast.csv --suite s3 --configs fast --reps 3 --jobs 2
step s4 python3 hf_benign4.py $OUT/s4_fast.csv --configs fast --reps 3 --jobs 2
echo ALLDONE > $OUT/DONE
