#!/usr/bin/env python3
"""S5: provenance stress suite. Benign workloads that READ a file and then overwrite it in place with high-entropy data over
high-entropy originals -- the cases a read-before-write signal is most likely to get wrong -- plus controls that do not read first.
Written to be adversarial to our own signal. Usage: hf_benign5.py OUT.csv --configs holdfast,prov --reps 3 --jobs 2"""
import argparse, os, random, glob, subprocess
import hf_benign as hb
import hf_benign2 as b2
from hf_lib import *
from hf_benign import mk_media, same_tree
b2.S['s5'] = []
def wl(*a): b2.wl('s5', *a)
def n(c, pat, k): return len(glob.glob(c['M'] + pat)) == k
def noise(c, d, k, seed=None):
    r = random.Random(seed) if seed else c['rng']; os.makedirs(d, exist_ok=True)
    for i in range(k): open(f'{d}/f{i}.bin', 'wb').write(r.randbytes(40000))

# ---- READ FIRST, overwrite noise over noise in place (the hard cases)
def s_enc(c):
    os.makedirs(c['B'] + '/v', exist_ok=True)
    for i in range(16):
        p = f"{c['SRC']}/p{i}"; open(p, 'wb').write(c['rng'].randbytes(30000))
        subprocess.run(f"openssl enc -aes-256-cbc -pbkdf2 -pass pass:old -in {p} -out {c['B']}/v/f{i}.enc", shell=True)
wl('reencrypt_vault_inplace', s_enc, "for f in v/*.enc; do openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:old -in $f | openssl enc -aes-256-cbc -pbkdf2 -pass pass:new > $SRC/t && cat $SRC/t > $f; done", lambda c: n(c, '/v/*.enc', 16))
wl('rsync_checksum_over_existing_noise', lambda c: (noise(c, c['B'] + '/d', 24), noise(c, c['SRC'] + '/n', 24, seed=3)), 'rsync -a --inplace --checksum $SRC/n/ ./d/', lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/d'))
wl('verify_hash_then_overwrite', lambda c: (noise(c, c['B'] + '/d', 24), noise(c, c['SRC'] + '/n', 24, seed=4)), "python3 -c \"import os,hashlib,glob\nfor f in sorted(glob.glob('d/*.bin')):\n    old=hashlib.sha256(open(f,'rb').read()).hexdigest()\n    new=open(os.environ['SRC']+'/n/'+os.path.basename(f),'rb').read()\n    if hashlib.sha256(new).hexdigest()!=old: open(f,'wb').write(new)\"", lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/d'))
wl('cmp_then_cp_over_noise', lambda c: (noise(c, c['B'] + '/d', 24), noise(c, c['SRC'] + '/n', 24, seed=5)), 'for f in d/*.bin; do cmp -s $SRC/n/$(basename $f) $f || cp $SRC/n/$(basename $f) $f; done', lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/d'))
def s_gz(c):
    os.makedirs(c['B'] + '/z', exist_ok=True)
    for i in range(20):
        open(f"{c['B']}/z/t{i}.txt", 'w').write(('word%d ' % i) * 4000)
    subprocess.run(f"gzip {c['B']}/z/*.txt", shell=True)
wl('recompress_gz_inplace', s_gz, "for f in z/*.gz; do zcat $f | gzip -9 > $SRC/t && cat $SRC/t > $f; done", lambda c: n(c, '/z/*.gz', 20))
wl('container_page_rewrite', lambda c: (os.makedirs(c['B'] + '/c'), [open(f"{c['B']}/c/vol{i}.img", 'wb').write(c['rng'].randbytes(200000)) for i in range(4)]), "python3 -c \"import os,glob\nfor f in glob.glob('c/*.img'):\n    fd=os.open(f,os.O_RDWR)\n    for o in range(0,200000,4096):\n        b=os.pread(fd,4096,o); os.pwrite(fd,bytes(x^1 for x in b),o)\n    os.close(fd)\"", lambda c: n(c, '/c/*.img', 4))
# ---- controls: no read of the destination
wl('cp_over_noise_noread', lambda c: (noise(c, c['B'] + '/d', 24), noise(c, c['SRC'] + '/n', 24, seed=6)), 'cp -f $SRC/n/*.bin d/', lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/d'))
wl('dd_notrunc_over_noise', lambda c: (noise(c, c['B'] + '/d', 24), noise(c, c['SRC'] + '/n', 24, seed=7)), 'for f in d/*.bin; do dd if=$SRC/n/$(basename $f) of=$f conv=notrunc 2>/dev/null; done', lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/d'))
wl('text_read_modify_write', lambda c: hb.mk_text(c['B'] + '/t', 40, c['rng']), "python3 -c \"import glob\nfor f in glob.glob('t/*.txt'):\n    s=open(f).read().replace('alpha','ALPHA'); open(f,'w').write(s)\"", lambda c: n(c, '/t/*.txt', 40))
wl('jpeg_read_modify_write_same_type', lambda c: mk_media(c['B'] + '/m', 20, c['rng']), "python3 -c \"import glob\nfor f in glob.glob('m/*.jpg'):\n    b=bytearray(open(f,'rb').read()); b[100]^=1; open(f,'wb').write(b)\"", lambda c: n(c, '/m/*.jpg', 20))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('out'); ap.add_argument('--configs', default='holdfast,prov')
    ap.add_argument('--reps', type=int, default=3); ap.add_argument('--jobs', type=int, default=2); ap.add_argument('--only', default='')
    a = ap.parse_args(); a.suite = 's5'; b2.run_suite(a)
