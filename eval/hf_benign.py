#!/usr/bin/env python3
"""Broad benign-workload suite (written BEFORE it was run against the frozen build; see CODE_FREEZE_SHA256.txt).
Usage: hf_benign.py OUT.csv --configs holdfast,restore_only,redirect_only --reps 3 --jobs 2"""
import argparse, csv, concurrent.futures as cf, random, os, time, subprocess, shutil, base64, textwrap
from hf_lib import *

def mk_media(d, n, rng, magic=b'\xff\xd8\xff\xe0', size=200_000, prefix='img', ext='jpg'):
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        open(f'{d}/{prefix}{i}.{ext}', 'wb').write(magic + rng.randbytes(size))
def mk_text(d, n, rng, size=6000, prefix='note', ext='txt'):
    os.makedirs(d, exist_ok=True)
    words = ['alpha','beta','gamma','delta','invoice','report','meeting','budget','draft','final']
    for i in range(n):
        open(f'{d}/{prefix}{i}.{ext}', 'w').write('\n'.join(' '.join(rng.choice(words) for _ in range(12)) for _ in range(size // 70)))
def mk_c_project(d, n, rng):
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        open(f'{d}/f{i}.c', 'w').write(f'int f{i}(int x){{ int s=0; for(int k=0;k<x;k++) s+=k*{i+1}; return s; }}\n')
    open(f'{d}/main.c', 'w').write('#include <stdio.h>\n' + ''.join(f'int f{i}(int);\n' for i in range(n)) + 'int main(){int t=0;' + ''.join(f't+=f{i}(3);' for i in range(n)) + 'printf("%d\\n",t);return 0;}\n')
    open(f'{d}/Makefile', 'w').write('OBJS=$(patsubst %.c,%.o,$(wildcard *.c))\napp: $(OBJS)\n\tgcc -o app $(OBJS)\n%.o: %.c\n\tgcc -O1 -c $< -o $@\nclean:\n\trm -f *.o app\n')

# Each workload: (name, setup(ctx), command (str run via sh in cwd=M), verify(ctx)->bool)
# ctx: dict with M, B, SRC (outside the mount), rng
W = []
def wl(name, setup, cmd, verify): W.append((name, setup, cmd, verify))

def same_tree(a, b): return md5_tree(a, False) == md5_tree(b, False)

wl('cp_r_new_media', lambda c: mk_media(c['SRC'] + '/media', 30, c['rng']), 'cp -r $SRC/media ./dest', lambda c: same_tree(c['SRC'] + '/media', c['M'] + '/dest'))
wl('tar_czf_media', lambda c: mk_media(c['SRC'] + '/media', 30, c['rng']), 'tar czf a.tgz -C $SRC media', lambda c: sh(f"tar tzf {c['M']}/a.tgz | wc -l").stdout.strip() == '31')
def s_tarx(c): mk_media(c['SRC'] + '/media', 30, c['rng']); sh(f"tar cf {c['SRC']}/m.tar -C {c['SRC']} media")
wl('tar_xf_media', s_tarx, 'tar xf $SRC/m.tar', lambda c: same_tree(c['SRC'] + '/media', c['M'] + '/media'))
wl('py_copy_media', lambda c: mk_media(c['SRC'] + '/media', 30, c['rng']), "python3 -c \"import shutil,glob,os\nos.makedirs('d',exist_ok=True)\nfor f in glob.glob(os.environ['SRC']+'/media/*'): shutil.copy(f,'d')\"", lambda c: same_tree(c['SRC'] + '/media', c['M'] + '/d'))
def s_rsync_over(c, magic=b'\xff\xd8\xff\xe0', kind='jpg'):
    mk_media(c['B'] + '/lib', 30, c['rng'], magic); mk_media(c['SRC'] + '/new', 30, c['rng'], magic)
wl('resync_over_existing_jpeg', s_rsync_over, 'cp -r $SRC/new/. ./lib/', lambda c: same_tree(c['SRC'] + '/new', c['M'] + '/lib'))
wl('resync_over_existing_unknown', lambda c: s_rsync_over(c, b''), 'cp -r $SRC/new/. ./lib/', lambda c: same_tree(c['SRC'] + '/new', c['M'] + '/lib'))
wl('rsync_over_existing_jpeg', s_rsync_over, 'rsync -a --inplace --checksum $SRC/new/ ./lib/', lambda c: same_tree(c['SRC'] + '/new', c['M'] + '/lib'))
wl('sed_i_text', lambda c: mk_text(c['B'] + '/t', 40, c['rng']), "for f in t/*.txt; do sed -i 's/alpha/ALPHA/g' $f; done", lambda c: all('alpha' not in open(p).read() for p in glob.glob(c['M'] + '/t/*.txt')))
def s_git(c): mk_text(c['B'] + '/repo', 60, c['rng'])
wl('git_workflow', s_git, "cd repo && git init -q && git add -A && git -c user.email=a@b -c user.name=n commit -qm one && git checkout -qb x && echo hi >> note1.txt && git -c user.email=a@b -c user.name=n commit -qam two && git gc -q --aggressive", lambda c: sh(f"cd {c['M']}/repo && git fsck 2>&1 | grep -ci error").stdout.strip() == '0')
wl('gcc_make_build', lambda c: mk_c_project(c['B'] + '/proj', 30, c['rng']), 'cd proj && make -j2 >/dev/null && make clean >/dev/null && make -j2 >/dev/null', lambda c: sh(f"{c['M']}/proj/app").returncode == 0)
wl('sqlite_inserts', lambda c: None, "python3 -c \"import sqlite3\nc=sqlite3.connect('t.db')\nc.execute('create table t(a,b)')\nfor i in range(30):\n    c.executemany('insert into t values(?,?)',[(j,'x'*50) for j in range(100)]); c.commit()\n\"", lambda c: sh(f"python3 -c \"import sqlite3;print(sqlite3.connect('{c['M']}/t.db').execute('select count(*) from t').fetchone()[0])\"").stdout.strip() == '3000')
wl('log_append', lambda c: open(c['B'] + '/app.log', 'w').write('start\n'), "python3 -c \"f=open('app.log','a')\nfor i in range(5000): f.write('line %d\\n'%i)\"", lambda c: sum(1 for _ in open(c['M'] + '/app.log')) == 5001)
wl('atomic_save_text', lambda c: mk_text(c['B'] + '/d', 40, c['rng']), "python3 -c \"import os,glob\nfor r in range(3):\n  for f in glob.glob('d/*.txt'):\n    s=open(f).read()+'x'\n    t=f+'.tmp'\n    fd=os.open(t,os.O_WRONLY|os.O_CREAT,0o644); os.write(fd,s.encode()); os.fsync(fd); os.close(fd); os.rename(t,f)\"", lambda c: all(open(p).read().endswith('xxx') for p in glob.glob(c['M'] + '/d/*.txt')))
def s_zip(c): mk_media(c['SRC'] + '/media', 30, c['rng']); mk_text(c['SRC'] + '/media', 10, c['rng'])
wl('zip_unzip', s_zip, 'zip -qr a.zip -j $SRC/media && mkdir -p out && unzip -qo a.zip -d out', lambda c: len(os.listdir(c['M'] + '/out')) == 40)
def s_img(c):
    from PIL import Image
    os.makedirs(c['B'] + '/photos', exist_ok=True)
    for i in range(20):
        im = Image.frombytes('RGB', (96, 96), c['rng'].randbytes(96 * 96 * 3)); im.save(f"{c['B']}/photos/p{i}.jpg", 'JPEG')
wl('reencode_jpeg_to_png_inplace', s_img, "python3 -c \"from PIL import Image\nimport glob\nfor f in glob.glob('photos/*.jpg'):\n    Image.open(f).convert('RGB').save(f,'PNG')\"", lambda c: all(open(p, 'rb').read(4) == b'\x89PNG' for p in glob.glob(c['M'] + '/photos/*.jpg')))
wl('download_large_new', lambda c: None, 'dd if=/dev/urandom of=big.bin bs=1M count=50 status=none', lambda c: os.path.getsize(c['M'] + '/big.bin') == 50 << 20)
wl('gzip_each_text', lambda c: mk_text(c['B'] + '/t', 30, c['rng']), 'gzip -9 t/*.txt', lambda c: len(glob.glob(c['M'] + '/t/*.gz')) == 30)
wl('openssl_encrypt_each', lambda c: mk_text(c['B'] + '/t', 30, c['rng']), 'for f in t/*.txt; do openssl enc -aes-256-cbc -pbkdf2 -in $f -out $f.enc -pass pass:x && rm $f; done', lambda c: len(glob.glob(c['M'] + '/t/*.enc')) == 30)
wl('rm_rf_tree', lambda c: mk_text(c['B'] + '/tree', 150, c['rng']), 'rm -rf tree', lambda c: not os.path.exists(c['M'] + '/tree'))
wl('logrotate_rename', lambda c: mk_text(c['B'] + '/logs', 12, c['rng'], prefix='svc', ext='log'), 'cd logs && for f in *.log; do mv $f $f.1; touch $f; done', lambda c: len(glob.glob(c['M'] + '/logs/*.log.1')) == 12)
wl('bulk_rename_jpeg_to_jpg', lambda c: mk_media(c['B'] + '/m', 30, c['rng'], ext='jpeg'), 'cd m && for f in *.jpeg; do mv $f ${f%.jpeg}.jpg; done', lambda c: len(glob.glob(c['M'] + '/m/*.jpg')) == 30)
wl('inplace_text_edit', lambda c: mk_text(c['B'] + '/t', 40, c['rng']), "python3 -c \"import glob\nfor f in glob.glob('t/*.txt'):\n    s=open(f).read().replace('beta','BETA'); open(f,'w').write(s)\"", lambda c: all('beta' not in open(p).read() for p in glob.glob(c['M'] + '/t/*.txt')))
wl('nightly_backup_overwrite', lambda c: (mk_media(c['SRC'] + '/media', 20, c['rng']), sh(f"tar czf {c['B']}/backup.tgz -C {c['SRC']} media")), 'tar czf backup.tgz -C $SRC media', lambda c: sh(f"tar tzf {c['M']}/backup.tgz | wc -l").stdout.strip() == '21')
wl('make_rebuild_objects', lambda c: mk_c_project(c['B'] + '/proj', 30, c['rng']), 'cd proj && make -j2 >/dev/null && touch f*.c && make -j2 >/dev/null', lambda c: sh(f"{c['M']}/proj/app").returncode == 0)
import glob

def run_one(args):
    cfg, wname, rep = args
    wl_ = [w for w in W if w[0] == wname][0]
    m = Mount(f'b_{cfg}_{wname}_{rep}', PRESETS[cfg])
    rng = random.Random(hash(wname) % 100000 + rep)
    res = dict(cfg=cfg, workload=wname, rep=rep)
    src = m.W + '/src'; os.makedirs(src)
    ctx = dict(M=m.M, B=m.B, SRC=src, rng=rng)
    try:
        wl_[1](ctx)
        m.start(); time.sleep(0.4)
        env = dict(os.environ, SRC=src)
        t0 = time.time()
        r = subprocess.run(['sh', '-c', wl_[2] + '; true'], cwd=m.M, env=env, capture_output=True, text=True, timeout=90, start_new_session=True)
        res['seconds'] = round(time.time() - t0, 2)
        time.sleep(0.5)
        ev = m.events()
        res['detections'] = sum(1 for e in ev if e.get('type') == 'detect')
        res['ambiguous_events'] = sum(1 for e in ev if e.get('type') == 'ambiguous')
        try: res['verified_live'] = int(bool(wl_[3](ctx)))
        except Exception as e: res['verified_live'] = 0
        time.sleep(2.8)                       # let held writes commit
        ctx['M'] = m.B                        # durable state = backing store
        try: res['verified_durable'] = int(bool(wl_[3](ctx)))
        except Exception: res['verified_durable'] = 0
    except subprocess.TimeoutExpired:
        res['error'] = 'timeout (workload blocked or frozen)'; res['detections'] = res.get('detections', 1)
    except Exception as e:
        res['error'] = str(e)[:100]
    finally:
        m.stop(); shutil.rmtree(m.W, ignore_errors=True)
    return res

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('out'); ap.add_argument('--configs', default='holdfast,restore_only,redirect_only')
    ap.add_argument('--reps', type=int, default=3); ap.add_argument('--jobs', type=int, default=2); ap.add_argument('--only', default='')
    a = ap.parse_args(); os.makedirs(WORK, exist_ok=True)
    names = [w[0] for w in W if not a.only or w[0] in a.only.split(',')]
    tasks = [(c, n, r) for c in a.configs.split(',') for n in names for r in range(a.reps)]
    random.Random(2).shuffle(tasks)
    done = set(); exists = os.path.exists(a.out)
    if exists:
        for r in csv.DictReader(open(a.out)): done.add((r['cfg'], r['workload'], int(r['rep'])))
        tasks = [t for t in tasks if t not in done]
        print('resuming, remaining', len(tasks), flush=True)
    f = ['cfg','workload','rep','seconds','detections','ambiguous_events','verified_live','verified_durable','error']
    with open(a.out, 'a' if exists else 'w', newline='') as fo, cf.ThreadPoolExecutor(a.jobs) as ex:
        w = csv.DictWriter(fo, fieldnames=f, extrasaction='ignore')
        if not exists: w.writeheader()
        for i, r in enumerate(ex.map(run_one, tasks)):
            w.writerow(r); fo.flush()
            if i % 10 == 0: print(f'{i}/{len(tasks)}', flush=True)
