#!/usr/bin/env python3
"""Holdfast visual demo panel (stdlib only).

    python3 scripts/holdfast_panel.py [--bin build] [--port 8765] [--dir ~/holdfast_panel]

Open http://127.0.0.1:8765 in a browser. One page lets you: check prerequisites, set up and mount a demo
corpus, launch simulated attackers (in the Holdfast mount AND, side by side, in an unprotected copy),
watch files and events live, and use release / discard / rollback. Only synthetic, harmless attackers
are used, and only on files the panel created. The server listens on localhost only."""
import argparse, hashlib, json, math, os, shutil, signal, subprocess, sys, threading, time, base64, random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument('--bin', default=os.path.join(HERE, '..', 'build'))
ap.add_argument('--port', type=int, default=8765)
ap.add_argument('--dir', default=os.path.expanduser('~/holdfast_panel'))
A = ap.parse_args()
BIN = os.path.abspath(A.bin); D = os.path.abspath(A.dir)
BACK, MNT, PLAIN = f'{D}/backing', f'{D}/mount', f'{D}/unprotected'
LOCK = threading.Lock()
PROCS = []          # attacker Popen handles
N_FILES = 20


def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f'error: {e}'


def mounted():
    return os.path.ismount(MNT)


def ent(b):
    if not b: return 0.0
    c = [0] * 256
    for x in b: c[x] += 1
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c if v)


def make_corpus(dst, kind='mix'):
    r = random.Random(7)
    os.makedirs(dst, exist_ok=True)
    for i in range(1, N_FILES + 1):
        # readable text documents so damage is visible; a third are JPEG-like and a third ZIP-like binaries
        k = i % 3
        if kind == 'blobs':       # unknown-format, already high-entropy data: the honest blind spot
            body = r.randbytes(r.randint(8000, 24000))
        elif k == 0:
            body = ('Quarterly report %d\n' % i + ''.join('line %d: customer record %d status ok\n' % (j, r.randint(1000, 9999)) for j in range(300))).encode()
        elif k == 1:
            body = b'\xff\xd8\xff\xe0' + bytes(r.choices(range(0, 256), weights=[8 if x < 128 else 1 for x in range(256)], k=r.randint(8000, 30000)))
        else:
            body = b'PK\x03\x04' + base64.encodebytes(r.randbytes(r.randint(8000, 24000)))
        open(f'{dst}/doc{i}.txt', 'wb').write(body)


def prereq():
    out = []
    for name, ok, hint in [
        ('rrfs_fuse binary', os.access(f'{BIN}/rrfs_fuse', os.X_OK), 'build it: cmake -S . -B build && cmake --build build'),
        ('rrfs_ctl binary', os.access(f'{BIN}/rrfs_ctl', os.X_OK), 'same build step'),
        ('/dev/fuse present', os.path.exists('/dev/fuse'), 'needs FUSE (WSL2 Ubuntu or Linux; run ./install.sh)'),
        ('fusermount3 installed', shutil.which('fusermount3') is not None, 'sudo apt install fuse3'),
        ('python3', True, ''),
    ]:
        out.append({'name': name, 'ok': ok, 'hint': hint})
    return out


def rm_tree(path):
    """rmtree that copes with Holdfast's read-only checkpoint directories (mode 0555)."""
    def fix(func, p, exc):
        try:
            os.chmod(os.path.dirname(p), 0o755); os.chmod(p, 0o755)
        except OSError:
            pass
        try: func(p)
        except OSError: pass
    for root, dirs, files in os.walk(path):
        for d in dirs:
            try: os.chmod(os.path.join(root, d), 0o755)
            except OSError: pass
    try: os.chmod(path, 0o755)
    except OSError: pass
    if sys.version_info >= (3, 12): shutil.rmtree(path, onexc=fix)
    else: shutil.rmtree(path, onerror=fix)


def force_clean():
    """Stop everything this panel started, unmount, and delete the panel's own data folder."""
    if os.path.basename(D.rstrip('/')) in ('', 'home') or D in ('/', os.path.expanduser('~')) or not (
            os.path.exists(f'{D}/manifest.json') or os.path.basename(D).startswith('holdfast_panel') or os.path.exists(f'{D}/backing')):
        return {'ok': False, 'log': f'Refusing to delete {D}: it does not look like a panel data folder.'}
    kill_attackers()
    for pid in os.listdir('/proc'):                      # leftover daemons serving our mount
        if pid.isdigit():
            try:
                cmd = open(f'/proc/{pid}/cmdline', 'rb').read().split(b'\0')
                if cmd and os.path.basename(cmd[0].decode(errors='ignore')) == 'rrfs_fuse' and BACK.encode() in cmd:
                    os.kill(int(pid), signal.SIGCONT); os.kill(int(pid), signal.SIGTERM)
            except Exception:
                pass
    time.sleep(0.3)
    ok = unmount_clean()
    if not ok: return {'ok': False, 'log': f'Could not unmount {MNT}; close shells inside it and run: fusermount3 -uz {MNT}'}
    if os.path.exists(D): rm_tree(D)
    if os.path.exists(D): return {'ok': False, 'log': f'{D} still exists; delete it by hand: rm -rf {D}'}
    return {'ok': True, 'log': f'Deleted {D}'}


def unmount_clean():
    """Unmount MNT (also a stale one left by an earlier run) and wait until it is really gone."""
    for _ in range(25):
        try:
            if not os.path.ismount(MNT): return True
        except OSError:
            pass                       # "Transport endpoint is not connected": a dead mount, still needs unmounting
        sh(['fusermount3', '-u', MNT]); sh(['fusermount3', '-uz', MNT]); time.sleep(0.2)
    try: return not os.path.ismount(MNT)
    except OSError: return False


def setup(kind='mix', strict=False):
    teardown()
    if not unmount_clean():
        return {'ok': False, 'log': f'Could not unmount {MNT}. Close any shell or file manager inside it, then run: fusermount3 -uz {MNT}'}
    if os.path.exists(D): rm_tree(D)
    for p in (BACK, MNT, PLAIN): os.makedirs(p, exist_ok=True)
    if os.listdir(BACK) or os.listdir(PLAIN):
        return {'ok': False, 'log': f'{D} could not be cleared. Press "Force clean" (it stops leftover daemons and deletes the folder), then try again.', 'needs_clean': True}
    make_corpus(BACK, kind)
    shutil.copytree(BACK, PLAIN, dirs_exist_ok=True)
    manifest = {}
    for f in sorted(os.listdir(BACK)):
        b = open(f'{BACK}/{f}', 'rb').read()
        manifest[f] = hashlib.md5(b).hexdigest()
    json.dump(manifest, open(f'{D}/manifest.json', 'w'))
    open(f'{BACK}/rrfs.conf', 'w').write('baseline_interval_seconds = 0\nsuspend_on_detect = true\n' + ('read_provenance = true\n' if strict else ''))
    log = open(f'{D}/fuse.log', 'w')
    subprocess.Popen([f'{BIN}/rrfs_fuse', BACK, MNT, '-f'], stdout=log, stderr=log, start_new_session=True)
    for _ in range(80):
        if mounted(): break
        time.sleep(0.1)
    return {'ok': mounted(), 'log': '' if mounted() else open(f'{D}/fuse.log').read()[-600:]}


def kill_attackers():
    for p in PROCS:
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: pass
    PROCS.clear()


def teardown():
    kill_attackers()
    sh(['fusermount3', '-uz', MNT])


def attack(mode, target):
    root = MNT if target == 'protected' else PLAIN
    if target == 'protected' and not mounted(): return {'ok': False, 'err': 'not mounted'}
    cmd = f"cd '{root}' && sh -c 'python3 {HERE}/attacker.py {mode}; true'"
    p = subprocess.Popen(['sh', '-c', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    PROCS.append(p)
    return {'ok': True}


def benign(target):
    """Legitimate workload: a text editor saving files via temp+rename, one at a time."""
    root = MNT if target == 'protected' else PLAIN
    code = ("import os,time\nfor i in range(1,6):\n f='doc%d.txt'%(i*3)\n d=open(f,'rb').read()\n"
            " open(f+'.swp','wb').write(d+b'\\n(edited)\\n'); os.rename(f+'.swp',f); time.sleep(0.4)\n")
    p = subprocess.Popen(['sh', '-c', f"cd '{root}' && sh -c 'python3 -c \"{code}\"; true'"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    PROCS.append(p)
    return {'ok': True}


def tile_state(root, name, want):
    try:
        b = open(f'{root}/{name}', 'rb').read()
    except Exception:
        return {'name': name, 'state': 'missing', 'ent': 0}
    h = hashlib.md5(b).hexdigest()
    e = ent(b[:4096])
    txt = name.endswith('.txt') and b[:7] == b'Quarter'
    if h == want: st = 'intact'
    elif txt and b[:7] == b'Quarter': st = 'edited'
    else: st = 'encrypted' if e > 7.2 else 'changed'
    return {'name': name, 'state': st, 'ent': round(e, 2)}


EV_OFF = {}


def state(ev_from):
    mf = json.load(open(f'{D}/manifest.json')) if os.path.exists(f'{D}/manifest.json') else {}
    out = {'mounted': mounted(), 'prereq': prereq(), 'files': [], 'plain': [], 'events': [], 'offset': ev_from,
           'suspended': [], 'held': 0, 'checkpoints': [], 'attackers': sum(1 for p in PROCS if p.poll() is None)}
    if mf:
        names = sorted(mf, key=lambda s: int(s[3:-4]))
        if out['mounted']:
            out['files'] = [tile_state(MNT, n, mf[n]) for n in names]
            st = sh([f'{BIN}/rrfs_ctl', MNT, 'status'], 5)
            sect = None
            for line in st.splitlines():
                s = line.strip()
                if s.startswith('suspended pids'): sect = 'sus'
                elif s.startswith('held-back'):
                    sect = None
                    try: out['held'] = int(s.rsplit(':', 1)[1])
                    except Exception: pass
                elif s.startswith('checkpoints'): sect = 'ck'
                elif s.startswith('recent events'): sect = None
                elif sect == 'sus' and s and s != '(none)': out['suspended'].append(s)
                elif sect == 'ck' and s and not s.startswith('('): out['checkpoints'].append(s)
        out['plain'] = [tile_state(PLAIN, n, mf[n]) for n in names]
    p = f'{BACK}/.rrfs_state/events.log'
    if os.path.exists(p):
        size = os.path.getsize(p)
        if ev_from > size: ev_from = 0
        with open(p, 'rb') as f:
            f.seek(ev_from); data = f.read()
        end = data.rfind(b'\n') + 1
        for line in data[:end].splitlines():
            try: e = json.loads(line)
            except Exception: continue
            if e.get('type') == 'write': continue
            out['events'].append(e)
        out['offset'] = ev_from + end
    return out


def ctl(verb, arg):
    if verb == 'recover':      # take a recovery checkpoint from the original-byte ring, then roll back to the newest one
        sh([f'{BIN}/rrfs_ctl', MNT, 'promote', 'recover'], 20); time.sleep(0.4)
        d = f'{BACK}/.rrfs_state/checkpoints'
        cks = sorted(os.listdir(d)) if os.path.isdir(d) else []
        if not cks: return {'ok': True, 'out': 'no checkpoint available'}
        return {'ok': True, 'out': sh([f'{BIN}/rrfs_ctl', MNT, 'rollback', cks[-1]], 60)}
    if verb not in ('release', 'discard', 'rollback', 'resume', 'promote'): return {'ok': False}
    args = [f'{BIN}/rrfs_ctl', MNT, verb] + ([arg] if arg else [])
    return {'ok': True, 'out': sh(args, 20)}


def kill_all_stopped():
    # resume anything left frozen so the terminal that launched the panel stays usable
    for p in PROCS:
        try: os.killpg(p.pid, signal.SIGCONT)
        except Exception: pass


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send(self, obj, code=200, ctype='application/json'):
        b = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store'); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith('/api/state'):
            off = int(self.path.split('off=')[1]) if 'off=' in self.path else 0
            return self.send(state(off))
        self.send(PAGE.encode(), 200, 'text/html; charset=utf-8')

    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        q = json.loads(self.rfile.read(n) or b'{}') if n else {}
        try:
          with LOCK:
            p = self.path
            if p == '/api/setup': r = setup(q.get('corpus', 'mix'), bool(q.get('strict')))
            elif p == '/api/attack': r = attack(q.get('mode', 'inplace'), q.get('target', 'protected'))
            elif p == '/api/benign': r = benign(q.get('target', 'protected'))
            elif p == '/api/ctl': r = ctl(q.get('verb', ''), str(q.get('arg', '')))
            elif p == '/api/stop': kill_attackers(); r = {'ok': True}
            elif p == '/api/teardown': teardown(); r = {'ok': True}
            elif p == '/api/forceclean': r = force_clean()
            else: r = {'ok': False}
        except Exception as e:
            r = {'ok': False, 'log': f'{type(e).__name__}: {e}', 'err': str(e)}
        self.send(r)


PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holdfast Demo Panel</title>
<style>
:root{--bg:#0f1420;--card:#171e2e;--ink:#e6ebf5;--mute:#8b97b3;--ok:#2fbf71;--bad:#ff5468;--warn:#f5a524;--info:#4da3ff;--vio:#b07cff;--line:#26304a}
@media(prefers-color-scheme:light){:root{--bg:#f3f5fa;--card:#fff;--ink:#16203a;--mute:#5d6a88;--line:#dfe4f0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,Segoe UI,sans-serif}
header{padding:16px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--line)}
h1{font-size:20px;margin:0}h2{font-size:14px;margin:0 0 10px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
#banner{margin-left:auto;padding:8px 16px;border-radius:999px;font-weight:700;background:var(--line)}
#banner.ok{background:var(--ok);color:#06210f}#banner.bad{background:var(--bad);color:#fff;animation:p 1s infinite}#banner.warn{background:var(--warn);color:#2b1c00}
@keyframes p{50%{opacity:.6}}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;padding:16px 24px 32px;max-width:1500px;margin:auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.wide{grid-column:1/-1}
button{font:inherit;border:1px solid var(--line);background:var(--bg);color:var(--ink);padding:8px 14px;border-radius:8px;cursor:pointer;margin:0 6px 8px 0}
button:hover{border-color:var(--info)}button.pri{background:var(--info);color:#04182e;border-color:var(--info);font-weight:600}
button.dng{background:var(--bad);color:#fff;border-color:var(--bad)}button.good{background:var(--ok);color:#06210f;border-color:var(--ok);font-weight:600}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:6px}
.tile{border-radius:8px;padding:8px 4px;text-align:center;font-size:12px;border:2px solid transparent;transition:all .25s}
.tile b{display:block;font-size:13px}.tile i{font-style:normal;color:inherit;opacity:.8}
.intact{background:rgba(47,191,113,.16);border-color:var(--ok)}.edited{background:rgba(77,163,255,.16);border-color:var(--info)}
.encrypted,.changed{background:rgba(255,84,104,.2);border-color:var(--bad)}.missing{background:var(--line);opacity:.5}
.ev{font:12.5px/1.5 ui-monospace,Consolas,monospace;max-height:340px;overflow:auto}
.ev div{padding:2px 6px;border-left:3px solid var(--line);margin-bottom:2px}
.ev .detect,.ev .suspend{border-color:var(--bad);color:var(--bad)}.ev .detect_soft,.ev .ambiguous,.ev .cluster{border-color:var(--vio);color:var(--vio)}
.ev .repair,.ev .discard{border-color:var(--warn);color:var(--warn)}.ev .release,.ev .resume,.ev .rollback,.ev .promote{border-color:var(--ok);color:var(--ok)}
.chk{display:flex;gap:8px;align-items:baseline}.chk span{font-weight:700}.y{color:var(--ok)}.n{color:var(--bad)}
.stat{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:10px}.stat div{min-width:90px}.stat b{font-size:22px;display:block}
small{color:var(--mute)}#msg{color:var(--mute);min-height:1.4em}
</style></head><body>
<header><h1>Holdfast demo panel</h1><small>ransomware hold-back &amp; recovery &middot; synthetic attackers only</small><div id="banner">…</div></header>
<main>
<section class="card"><h2>1 &middot; Setup</h2><div id="pre"></div>
<label>Files: <select id="corpus"><option value="mix">documents, JPEG-like and ZIP-like files</option><option value="blobs">unknown-format random blobs (blind spot)</option></select></label><br>
<label><input type="checkbox" id="strict"> strict mode (read provenance: catches read-then-encrypt on unknown formats, may flag verify-then-overwrite tools)</label><br>
<button class="pri" onclick="setup()">Create demo files &amp; mount Holdfast</button><button onclick="post('teardown')">Unmount</button>
<button class="dng" onclick="forceClean()" title="Stops leftover Holdfast daemons, unmounts, and deletes the panel's data folder">Force clean (delete data folder)</button>
<div id="msg"></div></section>

<section class="card"><h2>2 &middot; Run something</h2>
<small>Targets: the protected Holdfast mount and an identical unprotected folder, so you can compare.</small><p>
<b>Attackers</b><br>
<button class="dng" onclick="atk('inplace')">Encrypt in place</button>
<button class="dng" onclick="atk('readenc')">Read, encrypt, write back (realistic)</button>
<button class="dng" onclick="atk('replace')">Write temp &amp; rename over</button>
<button class="dng" onclick="atk('perfile')">One process per file</button><br>
<b>Legitimate</b><br>
<button class="good" onclick="ben()">Editor saves (temp+rename)</button>
<button onclick="atk('benign-reencrypt')">Backup re-encrypts (benign look-alike)</button><br>
<label><input type="checkbox" id="both" checked> also run on the unprotected copy</label></p>
<button onclick="post('stop')">Stop attackers</button><button onclick="setup()">Reset everything</button></section>

<section class="card"><h2>3 &middot; Operator</h2>
<div class="stat"><div><b id="sus">0</b><small>frozen pids</small></div><div><b id="held">0</b><small>held writes</small></div><div><b id="ck">0</b><small>checkpoints</small></div></div>
<button class="good" onclick="ctl('release',pid())">Release frozen job</button>
<button onclick="ctl('discard',pid())">Discard its writes</button>
<button onclick="ctl('discard','cluster')">Discard cluster</button><br>
<button onclick="ctl('promote','')">Take checkpoint</button>
<button onclick="ctl('recover','')">Recover (rebuild from originals &amp; roll back)</button>
<pre id="ctlout" style="white-space:pre-wrap;font-size:12px;color:var(--mute);margin:8px 0 0"></pre></section>

<section class="card"><h2>Protected (Holdfast mount) &middot; <span id="c1"></span></h2><div class="grid" id="g1"></div>
<small>What a user sees reading the mount. Green = original content.</small></section>
<section class="card"><h2>Unprotected copy &middot; <span id="c2"></span></h2><div class="grid" id="g2"></div>
<small>Same files, no Holdfast. Red = encrypted by the simulator.</small></section>
<section class="card wide"><h2>Live events</h2><div class="ev" id="ev"></div></section>
</main>
<script>
let off=0,lastSus=[],evs=[];
const $=id=>document.getElementById(id);
async function post(p,b){const r=await fetch('/api/'+p,{method:'POST',body:JSON.stringify(b||{})});const j=await r.json();
 if(p==='setup'){off=0;$('ev').innerHTML='';$('msg').textContent=j.ok?($('corpus').value==='blobs'?'Mounted with unknown-format blobs. Holdfast cannot tell encryption from this data: expect a deferral or cluster hold (not a freeze), then use Roll back.':'Mounted. Pick an attack.'):('Mount failed: '+(j.log||''))}return j}
async function forceClean(){if(!confirm('Delete the panel data folder and stop any leftover Holdfast mount? Only demo files are removed.'))return;
 const j=await post('forceclean');$('msg').textContent=j.log||(j.ok?'Cleaned.':'Failed');off=0;$('ev').innerHTML=''}
function setup(){return post('setup',{corpus:$('corpus').value,strict:$('strict').checked})}
async function atk(m){await post('attack',{mode:m,target:'protected'});if($('both').checked)await post('attack',{mode:m,target:'plain'})}
async function ben(){await post('benign',{target:'protected'});if($('both').checked)await post('benign',{target:'plain'})}
function pid(){const m=(lastSus[0]||'').match(/\d+/);return m?m[0]:''}
async function ctl(v,a){const j=await post('ctl',{verb:v,arg:a});$('ctlout').textContent=j.out||'no frozen pid / nothing to do'}
async function rb(){const s=$('ckl').dataset.last;if(!s){$('ctlout').textContent='no checkpoint yet';return}ctl('rollback',s)}
function tiles(el,arr){el.innerHTML=arr.map(f=>`<div class="tile ${f.state}"><b>${f.name.replace('.txt','')}</b><i>${f.state} · H ${f.ent}</i></div>`).join('')}
function count(arr,s){return arr.filter(f=>f.state===s).length}
async function tick(){
 try{const r=await fetch('/api/state?off='+off);const s=await r.json();off=s.offset;lastSus=s.suspended;
 $('pre').innerHTML=s.prereq.map(p=>`<div class="chk"><span class="${p.ok?'y':'n'}">${p.ok?'✔':'✘'}</span>${p.name}${p.ok?'':` <small>— ${p.hint}</small>`}</div>`).join('');
 tiles($('g1'),s.files);tiles($('g2'),s.plain);
 const ok=count(s.files,'intact'),bad=s.files.length-ok-count(s.files,'edited');
 $('c1').textContent=s.files.length?`${ok} intact, ${bad} damaged`:'';
 const ok2=count(s.plain,'intact'),bad2=s.plain.length-ok2-count(s.plain,'edited');
 $('c2').textContent=s.plain.length?`${ok2} intact, ${bad2} damaged`:'';
 $('sus').textContent=s.suspended.length;$('held').textContent=s.held;$('ck').textContent=s.checkpoints.length;
 let ck=document.createElement('span');ck.id='ckl';const last=s.checkpoints.length?s.checkpoints[s.checkpoints.length-1].split(/\s+/)[0]:'';
 const old=$('ckl');if(old)old.dataset.last=last;else{const sp=document.createElement('span');sp.id='ckl';sp.dataset.last=last;sp.hidden=true;document.body.appendChild(sp)}
 for(const e of s.events){const d=document.createElement('div');d.className=e.type;
  const t=new Date(e.ts).toLocaleTimeString();d.textContent=`${t}  ${e.type}  ${e.pid?('pid '+e.pid+'  '):''}${e.path||''} ${e.score>=0&&e.score!=null?('score '+Number(e.score).toFixed(1)):''} ${(e.detail||'').slice(0,110)}`;
  $('ev').prepend(d)}
 const b=$('banner');
 if(!s.mounted){b.className='';b.textContent='Not mounted'}
 else if(s.suspended.length){b.className='bad';b.textContent='ATTACK FROZEN · originals intact'}
 else if(s.held>0){b.className='warn';b.textContent='Writes held back'}
 else if(bad>0){b.className='bad';b.textContent='Files damaged'}
 else{b.className='ok';b.textContent=s.attackers?'Watching…':'Protected'}
 }catch(e){$('banner').textContent='panel offline'}
 setTimeout(tick,700)}
tick();
</script></body></html>'''


if __name__ == '__main__':
    try:
        srv = ThreadingHTTPServer(('127.0.0.1', A.port), H)
    except OSError as e:
        sys.exit(f'cannot listen on {A.port}: {e}')
    print(f'Holdfast panel: http://127.0.0.1:{A.port}   (data in {D}; Ctrl-C to stop and unmount)', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        kill_all_stopped(); teardown()
