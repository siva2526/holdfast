#!/usr/bin/env python3
"""End-to-end checks of release and crash recovery.
A) release undoes the detection-time namespace repair: a benign job that writes temp files and renames them over its
   documents is frozen; repair restores the originals; `release` puts the job's files back (the restored versions are kept in .rrfs_state/undo).
B) shelved writes survive a daemon crash: after kill -9 and a remount, `release <old pid>` still commits them."""
import os, time, subprocess, random, signal, json, shutil
from hf_lib import *
res = {}
def wait_detect(m, t=20):
    dl = time.time() + t
    while time.time() < dl:
        d = [e for e in m.events() if e.get('type') == 'detect']
        if d: return d
        time.sleep(0.1)
    return []
def spawn(m, body):
    return subprocess.Popen(['sh', '-c', 'python3 -c "$0"; true', body], cwd=m.M, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ---- A: namespace repair undone by release
m = Mount('rel53a', PRESETS['holdfast']); rng = random.Random(5)
orig = make_corpus(m.B, 'mixed', 20, rng); m.start(); time.sleep(0.4)
body = "import os\nfor f in sorted(x for x in os.listdir('.') if x.startswith('doc')):\n    n=os.path.getsize(f); open(f+'.new','wb').write(os.urandom(n)); os.rename(f+'.new', f)\nopen('done.flag','w').write('1')\n"
p = spawn(m, body); det = wait_detect(m); time.sleep(0.8)
pid = det[0]['pid'] if det else None
intact_after_detect = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.M, k)) == h)
r = sh([BIN + '/rrfs_ctl', m.M, 'release', str(pid)], timeout=30); time.sleep(1.0)
changed_after_release = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.M, k)) != h)
undo_dir = m.B + '/.rrfs_state/undo'
kept = sum(len(fs) for _, _, fs in os.walk(undo_dir)) if os.path.isdir(undo_dir) else 0
res['A'] = dict(detected=bool(det), live_intact_after_detect=intact_after_detect, of=len(orig), live_changed_after_release=changed_after_release,
                restored_versions_kept_in_undo=kept, ctl=(r.stdout + r.stderr).strip().splitlines()[0][:160] if (r.stdout + r.stderr).strip() else '')
try: os.killpg(p.pid, signal.SIGKILL)
except Exception: pass
m.stop(); shutil.rmtree(m.W, ignore_errors=True)

# ---- B: crash recovery of shelved writes
m = Mount('rel53b', PRESETS['holdfast']); rng = random.Random(6)
orig = make_corpus(m.B, 'mixed', 20, rng); m.start(); time.sleep(0.4)
body = "import os\nfor f in sorted(x for x in os.listdir('.') if x.startswith('doc')):\n    n=os.path.getsize(f); open(f,'wb').write(os.urandom(n))\n"
p = spawn(m, body); det = wait_detect(m); time.sleep(0.8)
pid = det[0]['pid'] if det else None
manifest = m.B + '/.rrfs_state/pending/shelf.manifest'
had_manifest = os.path.exists(manifest) and os.path.getsize(manifest) > 0
os.kill(m.proc.pid, signal.SIGKILL); time.sleep(0.5); sh(['fusermount3', '-uz', m.M]); time.sleep(0.3)
try: os.killpg(p.pid, signal.SIGKILL)
except Exception: pass
store_intact = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.B, k)) == h)
m.start(); time.sleep(0.5)
r = sh([BIN + '/rrfs_ctl', m.M, 'release', str(pid)], timeout=30); time.sleep(0.8)
changed = sum(1 for k, h in orig.items() if md5_file(os.path.join(m.B, k)) != h)
res['B'] = dict(detected=bool(det), manifest_written=had_manifest, store_intact_after_crash=store_intact, of=len(orig),
                files_committed_by_release_after_restart=changed, ctl=(r.stdout + r.stderr).strip().splitlines()[0][:160] if (r.stdout + r.stderr).strip() else '')
m.stop(); shutil.rmtree(m.W, ignore_errors=True)
print(json.dumps(res, indent=1))
