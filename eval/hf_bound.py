#!/usr/bin/env python3
"""Loss-bound validation: a single attacker keeps the fast score low by pacing at rate r files/s."""
import csv, sys, os, concurrent.futures as cf
import hf_lib, hf_attack as A
from hf_lib import PRESETS

RATES = [0.5, 1.0, 2.0, 5.0, 20.0]
def main(out, trials=5, jobs=3):
    tasks = []
    for r in RATES:
        key = f'rate_{r}'
        A.ATTACKS[key] = A.loop(f"fd=os.open(f,os.O_WRONLY); os.pwrite(fd,os.urandom(os.path.getsize(f)),0); os.close(fd); time.sleep({1.0/r})")
        A.TIMEOUT[key] = 25 + int(40 / r)
        for cfg in ('holdfast', 'restore_only', 'no_slow'):
            for corpus in ('mixed',):
                for t in range(trials): tasks.append((cfg, corpus, key, t, 777 + t))
    with cf.ThreadPoolExecutor(jobs) as ex: rows = list(ex.map(A.run_trial, tasks))
    keys = sorted({k for r in rows for k in r})
    with open(out, 'w', newline='') as fo:
        w = csv.DictWriter(fo, fieldnames=keys); w.writeheader(); [w.writerow(r) for r in rows]
if __name__ == '__main__': main(sys.argv[1])
