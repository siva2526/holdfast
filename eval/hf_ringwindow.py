#!/usr/bin/env python3
"""RING WINDOW variant of hf_blind: baseline interval 2 s, ring_size 3 (window about 6 s); wait W seconds after an undetected attack before the blind recover.
'Assume detection fails': attackers that never trigger a detection or an alert. A blind operator who notices the damage later runs
`promote recover` (checkpoint rebuilt from the original-byte ring) and `rollback`. How many originals come back, as a function of how many times
the attacker rewrote each file (the ring keeps ring_size generations)? Usage: hf_blind.py OUT.csv"""
import sys, csv, random, os, time, subprocess, signal, shutil, concurrent.futures as cf
import hf_attack as A
from hf_lib import *
for k in (1, 4, 8, 9, 12):
    A.ATTACKS[f'multi_hex_{k}'] = A.loop(f"for _ in range({k}):\n    n=os.path.getsize(f); open(f,'wb').write(os.urandom(n//2).hex().encode())")
    A.TIMEOUT[f'multi_hex_{k}'] = 60
CASES = ['hex_lowentropy', 'daemonized_per_file', 'forked_per_file', 'exfil_delete'] + [f'multi_hex_{k}' for k in (4, 8, 9, 12)]
def trial(args):
    cor, atk, t, W = args
    rng = random.Random(4242 + t * 31 + len(atk)); n = rng.randint(16, 32)
    m = Mount(f'rw_{cor}_{atk}_{t}_{W}', dict(PRESETS['holdfast'], baseline_interval_seconds=2, ring_size=3)); res = dict(corpus=cor, attack=atk, trial=t, n=n, wait=W)
    try:
        orig = make_corpus(m.B, cor, n, rng); m.start(); time.sleep(0.5)
        p = subprocess.Popen(['sh', '-c', 'python3 -c "$0"; true', A.ATTACKS[atk]], cwd=m.M, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        dl = time.time() + A.TIMEOUT.get(atk, 25)
        while time.time() < dl and p.poll() is None: time.sleep(0.1)
        time.sleep(0.5); ev = m.events()
        res['detected'] = int(any(e.get('type') == 'detect' for e in ev))
        res['alert'] = int(any(e.get('type') in ('detect_soft', 'cluster', 'ambiguous') for e in ev))
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: pass
        time.sleep(3.0 + W)
        res['intact_before'] = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.B, k)) == h)
        sh([BIN + '/rrfs_ctl', m.M, 'promote', 'recover'], timeout=30); time.sleep(0.5)
        m.rollback_latest(); time.sleep(0.5)
        res['intact_after_blind_recover'] = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.B, k)) == h)
    except Exception as e: res['error'] = str(e)[:100]
    finally: m.stop(); shutil.rmtree(m.W, ignore_errors=True)
    return res
if __name__ == '__main__':
    tasks = [('unknown', 'hex_lowentropy', t, W) for W in (0, 4, 12, 30) for t in range(5)]
    with cf.ThreadPoolExecutor(2) as ex: rows = list(ex.map(trial, tasks))
    keys = ['corpus', 'attack', 'trial', 'wait', 'n', 'detected', 'alert', 'intact_before', 'intact_after_blind_recover', 'error']
    with open(sys.argv[1], 'w', newline='') as fo:
        w = csv.DictWriter(fo, fieldnames=keys, extrasaction='ignore'); w.writeheader(); [w.writerow(r) for r in rows]
