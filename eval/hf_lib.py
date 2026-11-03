"""Shared helpers for the Holdfast evaluation harness (mount lifecycle, presets, corpora, metrics)."""
import os, sys, json, time, random, shutil, subprocess, hashlib, signal, math, glob, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
BIN = os.environ.get('HF_BIN', os.path.join(ROOT, 'build'))
WORK = os.environ.get('HF_WORK', '/tmp/hf_work')

# Decision-principle presets. The two baselines are re-implementations of the
# PRINCIPLE of each published system inside this codebase, not the original systems.
BASE = {'baseline_interval_seconds': 0, 'suspend_on_detect': 'true'}
PRESETS = {
    'holdfast': {},
    'prov': {'read_provenance': 'true'},
    'fast': {'holdback_fast_copy': 'true'},
    'holdfast_freeze': {'ambiguous_policy': 'freeze'},
    # ShieldFS-style: shadow-copy on first write, score, detect, restore AFTER the fact; no hold-back,
    # no content-delta/type signal, no slow-burn, no parent aggregation, no scoped repair.
    'restore_only': {'holdback_enabled': 'false', 'content_delta_enabled': 'false', 'slow_burn_files': 1000000,
                     'aggregate_by_parent': 'false', 'repair_on_detect': 'false', 'ambiguous_policy': 'off', 'graded_response': 'false', 'shelve_on_detect': 'false', 'type_conversion_benign': 'false'},
    # Redemption-style: writes redirected and committed only after the writer looks benign; entropy-change
    # (no file-type signal), no slow-burn, no parent aggregation, no scoped namespace repair.
    'redirect_only': {'holdback_enabled': 'true', 'content_delta_enabled': 'true', 'w_type_destroyed': 0.0,
                      'slow_burn_files': 1000000, 'aggregate_by_parent': 'false', 'repair_on_detect': 'false',
                      'ambiguous_policy': 'off', 'graded_response': 'false', 'shelve_on_detect': 'false', 'type_conversion_benign': 'false'},
    # ablations of the full system
    'holdfast_defer_short': {'ambiguous_defer_ms': 1500},   # lets the deferral window expire inside a trial
    'no_slow': {'slow_burn_files': 1000000},
    'no_parent': {'aggregate_by_parent': 'false'},
    'no_delta': {'content_delta_enabled': 'false'},
    'no_amb': {'ambiguous_policy': 'off'},
}

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)

class Mount:
    def __init__(self, name, overrides=None):
        self.W = os.path.join(WORK, name); self.B = self.W + '/backing'; self.M = self.W + '/mount'
        sh(['fusermount3', '-uz', self.M]); shutil.rmtree(self.W, ignore_errors=True)
        os.makedirs(self.B); os.makedirs(self.M)
        self.overrides = dict(BASE); self.overrides.update(overrides or {})
    def start(self):
        shutil.copy(os.path.join(ROOT, 'rrfs.conf.example'), self.B + '/rrfs.conf')
        with open(self.B + '/rrfs.conf', 'a') as f:
            f.write('\n# harness overrides\n')
            for k, v in self.overrides.items(): f.write(f'{k} = {v}\n')
        log = open(self.W + '/fuse.log', 'w')
        self.proc = subprocess.Popen([BIN + '/rrfs_fuse', self.B, self.M, '-f'], stdout=log, stderr=log,
                                     stdin=subprocess.DEVNULL, start_new_session=True)
        for _ in range(60):
            if os.path.ismount(self.M): return self
            time.sleep(0.1)
        raise RuntimeError('mount failed: ' + open(self.W + '/fuse.log').read())
    def stop(self):
        sh(['fusermount3', '-uz', self.M]); time.sleep(0.2)
        try: self.proc.kill()
        except Exception: pass
        try: self.proc.wait(timeout=3)
        except Exception: pass
    def events(self):
        out = []
        try:
            for l in open(self.B + '/.rrfs_state/events.log'):
                try: out.append(json.loads(l))
                except Exception: pass
        except FileNotFoundError: pass
        return out
    def latest_ckpt(self):
        d = self.B + '/.rrfs_state/checkpoints'
        try: c = sorted(os.listdir(d))
        except FileNotFoundError: return None
        return c[-1] if c else None
    def rollback_latest(self):
        c = self.latest_ckpt()
        if not c: return False
        r = sh([BIN + '/rrfs_ctl', self.M, 'rollback', c], timeout=60)
        return r.returncode == 0

def md5_file(p):
    try:
        h = hashlib.md5()
        with open(p, 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
        return h.hexdigest()
    except Exception:
        return None

def md5_tree(d, skip_state=True):
    out = {}
    for dp, dn, fn in os.walk(d):
        if skip_state and '.rrfs_state' in dn: dn.remove('.rrfs_state')
        for f in fn:
            p = os.path.join(dp, f)
            if f == 'rrfs.conf': continue
            out[os.path.relpath(p, d)] = md5_file(p)
    return out

def make_corpus(B, kind, n, rng, size_lo=4096, size_hi=49152):
    """Seed n files doc<i>.txt directly in the backing dir. Returns {name: md5}."""
    import base64
    orig = {}
    for i in range(1, n + 1):
        sz = rng.randint(size_lo, size_hi)
        k = kind if kind != 'mixed' else ['text', 'jpeg', 'zip'][i % 3]
        raw = rng.randbytes(sz)
        if k == 'text': data = base64.encodebytes(raw)
        elif k == 'jpeg': data = b'\xff\xd8\xff\xe0' + raw
        elif k == 'zip': data = b'PK\x03\x04' + raw
        else: data = raw
        name = f'doc{i}.txt'
        with open(os.path.join(B, name), 'wb') as f: f.write(data)
        orig[name] = hashlib.md5(data).hexdigest()
    return orig

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))

def spread(xs):
    xs = sorted(xs); n = len(xs)
    if n == 0: return (0, 0, 0)
    return (xs[n // 2], xs[0], xs[-1])
