#!/usr/bin/env python3
"""Held-out benign suite S4 (24 workloads). Written before the later detector changes were evaluated; not used for tuning.
Usage: hf_benign4.py OUT.csv --configs holdfast --reps 3 --jobs 2"""
import argparse, os, random, glob, sys
import hf_benign as hb
import hf_benign2 as b2
from hf_lib import *
from hf_benign import mk_media, mk_text, same_tree
b2.S['s4'] = []
s = 's4'
def wl(*a): b2.wl(s, *a)
def n(c, pat, k): return len(glob.glob(c['M'] + pat)) == k
def mk_ini(d, k, rng):
    os.makedirs(d, exist_ok=True)
    for i in range(k): open(f'{d}/c{i}.ini', 'w').write(f'[main]\nname=svc{i}\nport={8000+i}\n[opts]\n' + ''.join(f'k{j}={rng.randint(0,999)}\n' for j in range(60)))
def mk_wav(d, k, rng):
    import struct, math
    os.makedirs(d, exist_ok=True)
    for i in range(k):
        data = b''.join(struct.pack('<h', int(8000 * math.sin(j / (5 + i)))) for j in range(12000))
        hdr = b'RIFF' + struct.pack('<I', 36 + len(data)) + b'WAVEfmt ' + struct.pack('<IHHIIHH', 16, 1, 1, 8000, 16000, 2, 16) + b'data' + struct.pack('<I', len(data))
        open(f'{d}/a{i}.wav', 'wb').write(hdr + data)
def mk_zips(d, k, rng, tag):
    import zipfile
    os.makedirs(d, exist_ok=True)
    for i in range(k):
        with zipfile.ZipFile(f'{d}/z{i}.zip', 'w', zipfile.ZIP_DEFLATED) as z: z.writestr('x.bin', rng.randbytes(9000) + tag.encode())

wl('touch_mtime_all', lambda c: mk_text(c['B'] + '/t', 60, c['rng']), 'touch -t 202001010000 t/*', lambda c: n(c, '/t/*.txt', 60))
wl('chmod_R_tree', lambda c: mk_text(c['B'] + '/t', 60, c['rng']), 'chmod -R go-w t', lambda c: n(c, '/t/*.txt', 60))
wl('split_then_cat_big', lambda c: open(c['B'] + '/big.bin', 'wb').write(c['rng'].randbytes(3_000_000)), 'split -b 500k big.bin part_ && cat part_* > joined.bin', lambda c: md5_file(c['M'] + '/joined.bin') == md5_file(c['M'] + '/big.bin'))
wl('truncate_logs_zero', lambda c: mk_text(c['B'] + '/l', 30, c['rng'], ext='log'), 'for f in l/*.log; do : > $f; done', lambda c: all(os.path.getsize(p) == 0 for p in glob.glob(c['M'] + '/l/*.log')))
wl('shelve_dbm_update', lambda c: None, "python3 -c \"import shelve\nd=shelve.open('s.db')\nfor i in range(300): d['k%d'%i]='v'*50\nd.close()\nd=shelve.open('s.db')\nfor i in range(300): d['k%d'%i]='w'*50\nd.close()\"", lambda c: len(glob.glob(c['M'] + '/s.db*')) >= 1)
wl('rsync_inplace_text_update', lambda c: (mk_text(c['B'] + '/d', 40, c['rng']), mk_text(c['SRC'] + '/n', 40, random.Random(77), prefix='note')), 'rsync -a --inplace --checksum $SRC/n/ ./d/', lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/d'))
def s_tar_u(c): mk_text(c['B'] + '/t', 20, c['rng']); sh(f"cd {c['B']} && tar cf a.tar t")
wl('tar_append_new_member', s_tar_u, 'echo more > extra.txt && tar rf a.tar extra.txt', lambda c: sh(f"tar tf {c['M']}/a.tar | grep -c extra.txt").stdout.strip() == '1')
wl('gunzip_edit_regzip_tmp', lambda c: (mk_text(c['B'] + '/g', 25, c['rng']), sh(f"gzip {c['B']}/g/*.txt")), "for f in g/*.gz; do zcat $f | sed 's/beta/BETA/' | gzip > $f.tmp && mv $f.tmp $f; done", lambda c: n(c, '/g/*.gz', 25))
wl('ini_rewrite_inplace', lambda c: mk_ini(c['B'] + '/i', 40, c['rng']), "python3 -c \"import configparser,glob\nfor f in glob.glob('i/*.ini'):\n    p=configparser.ConfigParser(); p.read(f); p['main']['port']='1'; p.write(open(f,'w'))\"", lambda c: all('port = 1' in open(p).read() for p in glob.glob(c['M'] + '/i/*.ini')))
wl('markdown_to_html_new', lambda c: mk_text(c['B'] + '/m', 30, c['rng'], ext='md'), "for f in m/*.md; do (echo '<html><body><pre>'; cat $f; echo '</pre></body></html>') > ${f%.md}.html; done", lambda c: n(c, '/m/*.html', 30))
wl('hardlink_dedupe', lambda c: (os.makedirs(c['B'] + '/h'), [open(f"{c['B']}/h/f{i}.txt", 'w').write('same content\n' * 500) for i in range(30)]), 'for f in h/f*.txt; do [ $f != h/f0.txt ] && ln -f h/f0.txt $f; done', lambda c: n(c, '/h/f*.txt', 30))
wl('zero_pad_renumber', lambda c: mk_text(c['B'] + '/r', 50, c['rng'], prefix='x'), "python3 -c \"import os,glob\nfor i,f in enumerate(sorted(glob.glob('r/x*.txt'))): os.rename(f,'r/%04d.txt'%i)\"", lambda c: n(c, '/r/00*.txt', 50))
wl('csv_append_rows', lambda c: (os.makedirs(c['B'] + '/c'), [open(f"{c['B']}/c/t{i}.csv", 'w').write('a,b\n' * 300) for i in range(30)]), 'for f in c/*.csv; do echo 1,2 >> $f; done', lambda c: all(open(p).read().endswith('1,2\n') for p in glob.glob(c['M'] + '/c/*.csv')))
wl('png_optimize_inplace', lambda c: b2.mk_photos(c, c['B'] + '/p', 15, ext='png', fmt='PNG'), 'mogrify -quality 95 p/*.png', lambda c: all(open(p, 'rb').read()[:4] == b'\x89PNG' for p in glob.glob(c['M'] + '/p/*.png')))
wl('wav_scale_inplace', lambda c: mk_wav(c['B'] + '/w', 15, c['rng']), "python3 -c \"import glob,struct\nfor f in glob.glob('w/*.wav'):\n    b=bytearray(open(f,'rb').read())\n    for i in range(44,len(b)-1,2):\n        v=struct.unpack('<h',b[i:i+2])[0]//2; b[i:i+2]=struct.pack('<h',v)\n    open(f,'wb').write(b)\"", lambda c: all(open(p, 'rb').read()[:4] == b'RIFF' for p in glob.glob(c['M'] + '/w/*.wav')))
def s_sqlite(c):
    sh(f"python3 -c \"import sqlite3;c=sqlite3.connect('{c['B']}/main.db');c.execute('create table t(a,b)');c.executemany('insert into t values(?,?)',[(j,'x'*40) for j in range(3000)]);c.commit()\"")
    open(c['SRC'] + '/x', 'w').write('1')
wl('sqlite_backup_over_existing', s_sqlite, "python3 -c \"import sqlite3\nsrc=sqlite3.connect('main.db'); dst=sqlite3.connect('main.db.bak'); src.backup(dst); dst.close()\nsrc=sqlite3.connect('main.db.bak'); dst=sqlite3.connect('main.db'); src.backup(dst)\"", lambda c: sh(f"python3 -c \"import sqlite3;print(sqlite3.connect('{c['M']}/main.db').execute('select count(*) from t').fetchone()[0])\"").stdout.strip() == '3000')
wl('cp_new_zip_over_old_zip', lambda c: (mk_zips(c['B'] + '/z', 20, c['rng'], 'old'), mk_zips(c['SRC'] + '/n', 20, random.Random(5), 'new')), 'cp -f $SRC/n/*.zip z/', lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/z'))
def s_enc(c): mk_text(c['SRC'] + '/t', 20, c['rng']); [sh(f"openssl enc -aes-256-cbc -pbkdf2 -pass pass:k -in {p} -out {c['B']}/e_{os.path.basename(p)}.enc") for p in glob.glob(c['SRC'] + '/t/*.txt')]
wl('openssl_decrypt_each_tmp', s_enc, "for f in e_*.enc; do openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:k -in $f -out ${f%.enc}.dec && rm $f; done", lambda c: n(c, '/e_*.dec', 20))
wl('base64_roundtrip_tmp', lambda c: mk_text(c['B'] + '/b', 25, c['rng']), "for f in b/*.txt; do base64 $f > $f.b64 && base64 -d $f.b64 > $f.tmp && mv $f.tmp $f && rm $f.b64; done", lambda c: n(c, '/b/*.txt', 25))
wl('iconv_convert_tmp_mv', lambda c: mk_text(c['B'] + '/i', 30, c['rng']), "for f in i/*.txt; do iconv -f utf-8 -t utf-16le $f > $f.tmp && mv $f.tmp $f; done", lambda c: n(c, '/i/*.txt', 30))
wl('dos2unix_sed_inplace', lambda c: (os.makedirs(c['B'] + '/d'), [open(f"{c['B']}/d/f{i}.txt", 'wb').write(b'line one\r\nline two\r\n' * 200) for i in range(30)]), "for f in d/*.txt; do sed -i 's/\\r$//' $f; done", lambda c: all(b'\r' not in open(p, 'rb').read() for p in glob.glob(c['M'] + '/d/*.txt')))
def s_zipmod(c): mk_text(c['SRC'] + '/t', 20, c['rng']); sh(f"cd {c['SRC']} && zip -qr t.zip t && cp t.zip {c['B']}/t.zip")
wl('unzip_modify_rezip_replace', s_zipmod, "mkdir w && cd w && unzip -q ../t.zip && sed -i 's/alpha/A/' t/*.txt && zip -qr ../t.new.zip t && cd .. && mv t.new.zip t.zip && rm -r w", lambda c: sh(f"unzip -tq {c['M']}/t.zip").returncode == 0)
wl('git_gc_aggressive', lambda c: (sh(f"cd {c['B']} && git init -q r && cd r && python3 -c \"import random\nfor i in range(40): open('f%d.txt'%i,'w').write('x%d\\n'%i*400)\" && git add -A && git -c user.email=a@b -c user.name=a commit -qm one"),), 'cd r && git gc --aggressive -q', lambda c: sh(f"cd {c['M']}/r && git fsck 2>&1 | grep -ci error").stdout.strip() == '0')
def s_bk(c): mk_text(c['B'] + '/bk', 6, c['rng'], prefix='backup.')
wl('rotate_backup_copies', s_bk, 'for i in 5 4 3 2 1 0; do [ -f bk/backup.$i.txt ] && cp bk/backup.$i.txt bk/backup.$((i+1)).txt; done; echo new > bk/backup.0.txt', lambda c: os.path.exists(c['M'] + '/bk/backup.6.txt'))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('out'); ap.add_argument('--configs', default='holdfast')
    ap.add_argument('--reps', type=int, default=3); ap.add_argument('--jobs', type=int, default=2); ap.add_argument('--only', default='')
    a = ap.parse_args(); a.suite = 's4'
    b2.run_suite(a)
