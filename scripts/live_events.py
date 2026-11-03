#!/usr/bin/env python3
"""Colourful live tail of Holdfast's event log, for presenting.  Usage: live_events.py <backing_dir>   (Ctrl-C to quit)
Shows only interesting events by default (use -a for every write)."""
import sys, os, time, json
C = {'detect': '\033[1;31m', 'suspend': '\033[31m', 'repair': '\033[33m', 'cluster': '\033[1;35m', 'detect_soft': '\033[35m',
     'ambiguous': '\033[35m', 'release': '\033[1;32m', 'resume': '\033[32m', 'promote': '\033[36m', 'rollback': '\033[1;36m',
     'discard': '\033[33m', 'cluster_block': '\033[35m', 'write': '\033[2m'}
args = [a for a in sys.argv[1:] if not a.startswith('-')]; show_all = '-a' in sys.argv
if not args: sys.exit(__doc__)
p = os.path.join(args[0], '.rrfs_state', 'events.log')
while not os.path.exists(p): time.sleep(0.3)
t0 = None
with open(p) as f:
    f.seek(0, 2) if '--from-end' in sys.argv else None
    while True:
        line = f.readline()
        if not line: time.sleep(0.15); continue
        try: e = json.loads(line)
        except Exception: continue
        t = e.get('type', '?')
        t0 = t0 or e['ts']
        if t == 'write' and not show_all: continue
        extra = e.get('detail') or ''
        print(f"{C.get(t, '')}{(e['ts'] - t0) / 1000:7.2f}s  {t:<12} pid={e.get('pid', ''):<7} {e.get('path', '') or ''} {('score=%.1f' % e['score']) if e.get('score', -1) >= 0 else ''}  {extra[:90]}\033[0m", flush=True)
