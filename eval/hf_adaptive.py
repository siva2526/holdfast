#!/usr/bin/env python3
"""C/D: randomised adaptive-attacker search against a frozen build. Each trial samples attacker parameters
(workers, pacing, chunking, coverage fraction, spawn style, rename/delete style) and records the files whose ORIGINAL content is
lost in the durable store (backing) after settle, with no manual recovery. Usage: hf_adaptive.py OUT.csv --configs holdfast,restore_only,redirect_only --n 40"""
import argparse, csv, random, os, time, subprocess, signal, shutil, json, concurrent.futures as cf
from hf_lib import *

def make_script(p):
    # p: workers, style(inplace|trunc|tmpren|encdel), chunk, pace, frac, spawn(thread-free: fork|setsid|dfork|subproc), order
    body = {
     'inplace': "fd=os.open(f,os.O_WRONLY)\nsz=os.path.getsize(f)\nfor o in range(0,int(sz*FRAC),CH): os.pwrite(fd,os.urandom(min(CH,sz-o)),o)\nos.close(fd)",
     'trunc': "n=os.path.getsize(f); open(f,'wb').write(os.urandom(max(1,int(n*FRAC))))",
     'tmpren': "n=os.path.getsize(f); open(f+'.tmp','wb').write(os.urandom(n)); os.rename(f+'.tmp',f)",
     'encdel': "n=os.path.getsize(f); open(f+'.enc','wb').write(os.urandom(n)); os.unlink(f)",
    }[p['style']]
    work = "def work(f):\n    " + body.replace('\n', '\n    ') + "\n"
    spawn = p['spawn']
    run = {
     'fork': "def run(f):\n    pid=os.fork()\n    if pid==0:\n        work(f); os._exit(0)\n    os.waitpid(pid,0)\n",
     'setsid': "def run(f):\n    pid=os.fork()\n    if pid==0:\n        os.setsid(); work(f); os._exit(0)\n    os.waitpid(pid,0)\n",
     'dfork': "def run(f):\n    pid=os.fork()\n    if pid==0:\n        os.setsid()\n        if os.fork()==0:\n            work(f); os._exit(0)\n        os._exit(0)\n    os.waitpid(pid,0)\n",
     'single': "def run(f):\n    work(f)\n",
    }[spawn]
    # W cooperating workers: each owns a slice of the files, started by one master (or by double fork)
    main = (f"files=sorted(f for f in os.listdir('.') if f.startswith('doc'))\nW={p['workers']}\n"
            "def slice_(i):\n    for f in files[i::W]:\n        run(f)\n        time.sleep(PACE)\n"
            "kids=[]\nfor i in range(W):\n    pid=os.fork()\n    if pid==0:\n        slice_(i); os._exit(0)\n    kids.append(pid)\n"
            "for k in kids: os.waitpid(k,0)\n")
    return f"import os,time\nFRAC={p['frac']}\nCH={p['chunk']}\nPACE={p['pace']}\n" + work + run + main

def sample(rng):
    return dict(workers=rng.choice([1, 1, 2, 4, 8, 16]), style=rng.choice(['inplace', 'trunc', 'tmpren', 'encdel']),
                chunk=rng.choice([256, 4096, 65536]), pace=rng.choice([0, 0, 0.05, 0.3, 1.0]),
                frac=rng.choice([1.0, 1.0, 0.5, 0.25, 0.1]), spawn=rng.choice(['single', 'fork', 'setsid', 'dfork']))

def trial(args):
    cfg, corpus, seed = args
    rng = random.Random(seed); p = sample(rng); n = rng.randint(24, 40)
    m = Mount(f'ad_{cfg}_{corpus}_{seed}', PRESETS[cfg]); res = dict(cfg=cfg, corpus=corpus, seed=seed, n=n, params=json.dumps(p))
    try:
        orig = make_corpus(m.B, corpus, n, rng); m.start(); time.sleep(0.4)
        pr = subprocess.Popen(['sh', '-c', 'python3 -c "$0"; true', make_script(p)], cwd=m.M, start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.time(); dl = t0 + 60
        while time.time() < dl and pr.poll() is None:
            if any(e.get('type') == 'detect' for e in m.events()): time.sleep(0.3); break
            time.sleep(0.2)
        try: os.killpg(pr.pid, signal.SIGKILL)
        except Exception: pass
        time.sleep(3.0)
        ev = m.events()
        res['detected'] = int(any(e.get('type') == 'detect' for e in ev))
        res['cluster'] = int(any(e.get('type') == 'cluster' for e in ev))
        res['durable_intact'] = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.B, k)) == h)
        # content survives even if renamed (enc/tmp variants leave originals only if never replaced)
        res['lost'] = n - res['durable_intact']
        # operator action: roll back to the newest checkpoint if the daemon raised a detection OR a cluster alert
        if res['detected'] or res['cluster']:
            m.rollback_latest(); time.sleep(0.6)
        res['recovered_intact'] = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.B, k)) == h)
        res['lost_after_recovery'] = n - res['recovered_intact']
    except Exception as e: res['error'] = str(e)[:100]
    finally: m.stop(); shutil.rmtree(m.W, ignore_errors=True)
    return res

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('out'); ap.add_argument('--configs', default='holdfast,restore_only,redirect_only')
    ap.add_argument('--corpora', default='mixed'); ap.add_argument('--n', type=int, default=40); ap.add_argument('--jobs', type=int, default=3)
    a = ap.parse_args(); os.makedirs(WORK, exist_ok=True)
    tasks = [(c, k, 5000 + i) for i in range(a.n) for k in a.corpora.split(',') for c in a.configs.split(',')]
    f = ['cfg','corpus','seed','n','params','detected','cluster','durable_intact','lost','recovered_intact','lost_after_recovery','error']
    with open(a.out, 'w', newline='') as fo, cf.ThreadPoolExecutor(a.jobs) as ex:
        w = csv.DictWriter(fo, fieldnames=f, extrasaction='ignore'); w.writeheader()
        for i, r in enumerate(ex.map(trial, tasks)): w.writerow(r); fo.flush(); print(i, flush=True) if i % 10 == 0 else None
