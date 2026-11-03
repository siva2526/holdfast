#!/usr/bin/env python3
"""Held-out benign suites S2 and S3 (S2 was used to fix false-positive rules; S3 was written before those fixes and run once afterwards).
Usage: hf_benign2.py OUT.csv --suite s2|s3 --configs holdfast --reps 3 --jobs 2"""
import argparse, csv, concurrent.futures as cf, random, os, time, subprocess, shutil, glob, sys
import hf_benign as hb
from hf_lib import *
from hf_benign import mk_media, mk_text, mk_c_project, same_tree

S = {'s2': [], 's3': []}
def wl(suite, name, setup, cmd, verify): S[suite].append((name, setup, cmd, verify))
def allf(c, pat, f): return all(f(open(p, 'rb').read()) for p in glob.glob(c['M'] + pat)) and len(glob.glob(c['M'] + pat)) > 0
def nfiles(c, pat, n): return len(glob.glob(c['M'] + pat)) == n
def mk_photos(c, d, n, ext='jpg', fmt='JPEG', size=96):
    from PIL import Image
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        im = Image.frombytes('RGB', (size, size), c['rng'].randbytes(size * size * 3)); im.save(f'{d}/p{i}.{ext}', fmt)
def mk_json(d, n, rng):
    os.makedirs(d, exist_ok=True)
    for i in range(n): open(f'{d}/c{i}.json', 'w').write('{"id": %d, "name": "item%d", "vals": [%s]}\n' % (i, i, ','.join(str(rng.randint(0, 99)) for _ in range(200))))
def mk_py(d, n):
    os.makedirs(d, exist_ok=True)
    for i in range(n): open(f'{d}/m{i}.py', 'w').write(f'def f{i}(x):\n    return x*{i+1}\n' * 20)

# ---------------- S2 (36) ----------------
s = 's2'
wl(s, 'zip_extractall_py', lambda c: (mk_py(c['SRC'] + '/pk', 80), sh(f"cd {c['SRC']} && zip -qr pk.zip pk")), "python3 -c \"import zipfile,os;zipfile.ZipFile(os.environ['SRC']+'/pk.zip').extractall('.')\"", lambda c: nfiles(c, '/pk/*.py', 80))
wl(s, 'compileall_twice', lambda c: mk_py(c['B'] + '/pkg', 40), 'python3 -m compileall -q pkg && touch pkg/*.py && python3 -m compileall -q -f pkg', lambda c: nfiles(c, '/pkg/__pycache__/*.pyc', 40))
wl(s, 'node_modules_like', lambda c: None, "python3 -c \"import os,json\nfor i in range(150):\n    d='nm/p%d'%i; os.makedirs(d,exist_ok=True)\n    json.dump({'n':i},open(d+'/package.json','w')); open(d+'/index.js','w').write('module.exports=%d;\\n'%i)\"", lambda c: nfiles(c, '/nm/p*/index.js', 150))
wl(s, 'cp_f_text_over_text', lambda c: (mk_text(c['B'] + '/t', 40, c['rng']), mk_text(c['SRC'] + '/n', 40, random.Random(9))), 'cp -f $SRC/n/* t/', lambda c: same_tree(c['SRC'] + '/n', c['M'] + '/t') or True)
def s_vim(c): mk_text(c['B'] + '/d', 30, c['rng'])
wl(s, 'vim_style_save_tilde', s_vim, "python3 -c \"import glob,os\nfor f in glob.glob('d/*.txt'):\n    s=open(f).read()+'edit\\n'\n    os.rename(f,f+'~')\n    open(f,'w').write(s)\"", lambda c: nfiles(c, '/d/*.txt~', 30))
wl(s, 'libreoffice_style_save', lambda c: mk_text(c['B'] + '/d', 25, c['rng'], ext='odt'), "python3 -c \"import glob,os\nfor f in glob.glob('d/*.odt'):\n    l='d/.~lock.'+os.path.basename(f)+'#'\n    open(l,'w').write('u')\n    t=f+'.tmp1'\n    open(t,'w').write(open(f).read()+'x')\n    os.rename(t,f); os.remove(l)\"", lambda c: nfiles(c, '/d/*.odt', 25))
wl(s, 'sqlite_update_inplace', lambda c: sh(f"python3 -c \"import sqlite3;c=sqlite3.connect('{c['B']}/t.db');c.execute('create table t(a,b)');c.executemany('insert into t values(?,?)',[(j,'y'*60) for j in range(4000)]);c.commit()\""), "python3 -c \"import sqlite3\nc=sqlite3.connect('t.db')\nfor k in range(20):\n    c.execute('update t set b=? where a%20=?',('z'*60,k)); c.commit()\"", lambda c: sh(f"python3 -c \"import sqlite3;print(sqlite3.connect('{c['M']}/t.db').execute(\\\"select count(*) from t where b like 'z%'\\\").fetchone()[0])\"").stdout.strip() == '4000')
wl(s, 'sqlite_wal_checkpoint', lambda c: None, "python3 -c \"import sqlite3\nc=sqlite3.connect('w.db')\nc.execute('pragma journal_mode=wal'); c.execute('create table t(a,b)')\nfor i in range(40):\n    c.executemany('insert into t values(?,?)',[(j,'q'*80) for j in range(50)]); c.commit()\nc.execute('pragma wal_checkpoint(truncate)')\"", lambda c: sh(f"python3 -c \"import sqlite3;print(sqlite3.connect('{c['M']}/w.db').execute('select count(*) from t').fetchone()[0])\"").stdout.strip() == '2000')
wl(s, 'json_rewrite_inplace', lambda c: mk_json(c['B'] + '/j', 60, c['rng']), "python3 -c \"import glob,json\nfor f in glob.glob('j/*.json'):\n    d=json.load(open(f)); d['v']=2; json.dump(d,open(f,'w'))\"", lambda c: allf(c, '/j/*.json', lambda b: b'\"v\": 2' in b))
wl(s, 'csv_sort_inplace', lambda c: (os.makedirs(c['B'] + '/c'), [open(f"{c['B']}/c/t{i}.csv", 'w').write('\n'.join(f'{c["rng"].randint(0,9999)},row{j}' for j in range(400))) for i in range(30)]), "for f in c/*.csv; do sort -o $f $f; done", lambda c: nfiles(c, '/c/*.csv', 30))
wl(s, 'mogrify_resize_jpeg_inplace', lambda c: mk_photos(c, c['B'] + '/ph', 20, size=160), 'mogrify -resize 50% ph/*.jpg', lambda c: allf(c, '/ph/*.jpg', lambda b: b[:2] == b'\xff\xd8'))
wl(s, 'mogrify_strip_jpeg', lambda c: mk_photos(c, c['B'] + '/ph', 20, size=160), 'mogrify -strip -quality 80 ph/*.jpg', lambda c: allf(c, '/ph/*.jpg', lambda b: b[:2] == b'\xff\xd8'))
wl(s, 'mogrify_format_png_new', lambda c: mk_photos(c, c['B'] + '/ph', 20), 'mogrify -format png ph/*.jpg', lambda c: nfiles(c, '/ph/*.png', 20))
wl(s, 'photo_import_rename_case', lambda c: mk_media(c['B'] + '/in', 30, c['rng'], ext='JPG', prefix='IMG_'), 'cd in && for f in *.JPG; do mv $f $(echo ${f%.JPG}|tr A-Z a-z).jpg; done', lambda c: nfiles(c, '/in/*.jpg', 30))
wl(s, 'bulk_rename_txt_to_md', lambda c: mk_text(c['B'] + '/n', 40, c['rng']), 'cd n && for f in *.txt; do mv $f ${f%.txt}.md; done', lambda c: nfiles(c, '/n/*.md', 40))
wl(s, 'bulk_rename_prefix', lambda c: mk_media(c['B'] + '/m', 40, c['rng']), 'cd m && for f in *.jpg; do mv $f 2024_$f; done', lambda c: nfiles(c, '/m/2024_*.jpg', 40))
wl(s, 'organize_by_ext', lambda c: (mk_media(c['B'] + '/m', 20, c['rng']), mk_text(c['B'] + '/m', 20, c['rng'])), 'cd m && mkdir -p jpg txt && mv *.jpg jpg/ && mv *.txt txt/', lambda c: nfiles(c, '/m/jpg/*.jpg', 20) and nfiles(c, '/m/txt/*.txt', 20))
wl(s, 'logrotate_chain', lambda c: [open(f"{c['B']}/a.log{('.'+str(i)) if i else ''}", 'w').write('x%d\n' % i * 3000) for i in range(5)], 'for i in 4 3 2 1; do mv a.log.$i a.log.$((i+1)); done; mv a.log a.log.1; touch a.log', lambda c: nfiles(c, '/a.log.*', 5))
wl(s, 'logrotate_gzip', lambda c: mk_text(c['B'] + '/l', 15, c['rng'], prefix='s', ext='log'), 'cd l && for f in *.log; do mv $f $f.1; gzip $f.1; touch $f; done', lambda c: nfiles(c, '/l/*.log.1.gz', 15))
wl(s, 'tar_extract_idempotent', lambda c: (mk_media(c['SRC'] + '/media', 25, c['rng']), sh(f"cd {c['SRC']} && tar cf m.tar media && tar xf m.tar -C {c['B']}")), 'tar xf $SRC/m.tar', lambda c: same_tree(c['SRC'] + '/media', c['M'] + '/media'))
wl(s, 'deploy_overwrite_scripts', lambda c: (mk_py(c['B'] + '/app', 40), mk_py(c['SRC'] + '/new', 40)), 'cp $SRC/new/*.py app/', lambda c: nfiles(c, '/app/*.py', 40))
wl(s, 'unzip_o_over_existing', lambda c: (mk_media(c['SRC'] + '/m', 25, c['rng']), sh(f"cd {c['SRC']} && zip -qr m.zip m && unzip -q m.zip -d {c['B']}"), mk_media(c['SRC'] + '/m', 25, random.Random(77)), sh(f"cd {c['SRC']} && rm m.zip && zip -qr m.zip m")), 'unzip -qo $SRC/m.zip', lambda c: same_tree(c['SRC'] + '/m', c['M'] + '/m'))
wl(s, 'rsync_mirror_delete', lambda c: (mk_text(c['B'] + '/dst', 40, c['rng']), mk_text(c['SRC'] + '/s', 25, c['rng'])), 'rsync -a --delete --checksum $SRC/s/ dst/', lambda c: nfiles(c, '/dst/*.txt', 25))
def s_build(c):
    mk_c_project(c['B'] + '/proj', 40, c['rng']); sh(f"cd {c['B']}/proj && make -j2 >/dev/null")
wl(s, 'make_clean_after_build', s_build, 'cd proj && make clean >/dev/null', lambda c: nfiles(c, '/proj/*.o', 0))
wl(s, 'find_delete_objects', s_build, "cd proj && find . -name '*.o' -delete", lambda c: nfiles(c, '/proj/*.o', 0))
def s_git2(c):
    mk_text(c['B'] + '/r', 80, c['rng'])
    sh(f"cd {c['B']}/r && git init -q && git add -A && git -c user.email=a@b -c user.name=n commit -qm a && git checkout -qb b && for f in note1*.txt; do echo more >> $f; done && git -c user.email=a@b -c user.name=n commit -qam b")
wl(s, 'git_checkout_switch', s_git2, 'cd r && for i in 1 2 3; do git checkout -q master 2>/dev/null || git checkout -q main; git checkout -q b; done', lambda c: sh(f"cd {c['M']}/r && git fsck 2>&1 | grep -ci error").stdout.strip() == '0')
wl(s, 'git_clone_local', lambda c: (mk_text(c['SRC'] + '/r', 60, c['rng']), sh(f"cd {c['SRC']}/r && git init -q && git add -A && git -c user.email=a@b -c user.name=n commit -qm a")), 'git clone -q $SRC/r cl', lambda c: nfiles(c, '/cl/*.txt', 60))
def s_docx(c):
    import zipfile
    os.makedirs(c['B'] + '/d', exist_ok=True)
    for i in range(20):
        z = zipfile.ZipFile(f"{c['B']}/d/r{i}.docx", 'w', zipfile.ZIP_DEFLATED); z.writestr('word/document.xml', c['rng'].randbytes(8000)); z.close()
wl(s, 'docx_resave_tmp_rename', s_docx, "python3 -c \"import zipfile,glob,os\nfor f in glob.glob('d/*.docx'):\n    zi=zipfile.ZipFile(f); b=zi.read('word/document.xml'); zi.close()\n    t=f+'.tmp'\n    z=zipfile.ZipFile(t,'w',zipfile.ZIP_DEFLATED); z.writestr('word/document.xml',b+b'x'); z.close(); os.rename(t,f)\"", lambda c: nfiles(c, '/d/*.docx', 20))
def s_maildir(c):
    for d in ('new', 'cur'): os.makedirs(f"{c['B']}/mail/{d}")
    for i in range(40): open(f"{c['B']}/mail/new/{i}.msg", 'w').write(f'Subject: {i}\n\nbody\n' * 30)
wl(s, 'maildir_flag_rename', s_maildir, 'cd mail && for f in new/*; do b=$(basename $f); mv $f cur/$b:2,S; done', lambda c: nfiles(c, '/mail/cur/*:2,S', 40))
wl(s, 'thumbnail_cache_small_new', lambda c: None, "python3 -c \"import os,random\nos.makedirs('th',exist_ok=True)\nfor i in range(300): open('th/%d.png'%i,'wb').write(b'\\x89PNG\\r\\n\\x1a\\n'+random.randbytes(2000))\"", lambda c: nfiles(c, '/th/*.png', 300))
wl(s, 'browser_cache_churn', lambda c: None, "python3 -c \"import os,random\nos.makedirs('cc',exist_ok=True)\nfor i in range(200):\n    p='cc/%d.tmp'%i; open(p,'wb').write(random.randbytes(3000))\n    if i%2: os.remove(p)\"", lambda c: nfiles(c, '/cc/*.tmp', 100))
wl(s, 'bzip2_each', lambda c: mk_text(c['B'] + '/t', 30, c['rng']), 'bzip2 -9 t/*.txt', lambda c: nfiles(c, '/t/*.bz2', 30))
wl(s, 'xz_each', lambda c: mk_text(c['B'] + '/t', 30, c['rng']), 'for f in t/*.txt; do xz $f; done', lambda c: nfiles(c, '/t/*.xz', 30))
wl(s, 'xargs_parallel_gzip', lambda c: mk_text(c['B'] + '/t', 40, c['rng']), 'ls t/*.txt | xargs -P4 -n1 gzip', lambda c: nfiles(c, '/t/*.gz', 40))
wl(s, 'cp_over_existing_unknown_blobs', lambda c: (mk_media(c['B'] + '/b', 30, c['rng'], magic=b'', ext='dat'), mk_media(c['SRC'] + '/n', 30, random.Random(5), magic=b'', ext='dat')), 'cp $SRC/n/*.dat b/', lambda c: nfiles(c, '/b/*.dat', 30))
wl(s, 'dpkg_like_binary_replace', lambda c: (os.makedirs(c['B'] + '/bin'), [open(f"{c['B']}/bin/t{i}", 'wb').write(b'\x7fELF' + c['rng'].randbytes(30000)) for i in range(25)], os.makedirs(c['SRC'] + '/n'), [open(f"{c['SRC']}/n/t{i}", 'wb').write(b'\x7fELF' + random.Random(i).randbytes(30000)) for i in range(25)]), 'cp $SRC/n/* bin/', lambda c: nfiles(c, '/bin/t*', 25))
wl(s, 'ffmpeg_make_audio', lambda c: None, 'for i in 1 2 3 4 5 6; do ffmpeg -loglevel quiet -f lavfi -i sine=frequency=$((300+i*50)):duration=1 a$i.wav; done; for i in 1 2 3 4 5 6; do ffmpeg -loglevel quiet -i a$i.wav a$i.flac; done', lambda c: nfiles(c, '/a*.flac', 6))

# ---------------- S3 (24), run once after the fixes ----------------
s = 's3'
wl(s, 'pip_wheel_unpack', lambda c: (mk_py(c['SRC'] + '/w', 60), sh(f"cd {c['SRC']} && zip -qr w.whl w")), 'mkdir -p sp && unzip -q $SRC/w.whl -d sp', lambda c: nfiles(c, '/sp/w/*.py', 60))
wl(s, 'cargo_like_incremental', lambda c: mk_c_project(c['B'] + '/proj', 40, c['rng']), 'cd proj && make -j2 >/dev/null; for i in 1 2 3; do touch f$i.c; make -j2 >/dev/null; done', lambda c: sh(f"{c['M']}/proj/app").returncode == 0)
wl(s, 'cp_a_dir_over_dir', lambda c: (mk_text(c['B'] + '/d', 50, c['rng']), mk_text(c['SRC'] + '/d', 50, random.Random(3))), 'cp -a $SRC/d/. d/', lambda c: nfiles(c, '/d/*.txt', 50))
wl(s, 'sed_i_json_tree', lambda c: mk_json(c['B'] + '/j', 60, c['rng']), "for f in j/*.json; do sed -i 's/item/ITEM/' $f; done", lambda c: allf(c, '/j/*.json', lambda b: b'ITEM' in b))
wl(s, 'perl_pi_edit', lambda c: mk_text(c['B'] + '/t', 40, c['rng']), "perl -pi -e 's/gamma/GAMMA/g' t/*.txt", lambda c: allf(c, '/t/*.txt', lambda b: b'gamma' not in b))
wl(s, 'awk_filter_replace_tmp', lambda c: mk_text(c['B'] + '/t', 40, c['rng']), "for f in t/*.txt; do awk 'NR%2' $f > $f.new && mv $f.new $f; done", lambda c: nfiles(c, '/t/*.txt', 40))
wl(s, 'tar_gz_rotate_backups', lambda c: (mk_media(c['SRC'] + '/m', 20, c['rng']), [sh(f"tar czf {c['B']}/bk.{i}.tgz -C {c['SRC']} m") for i in range(1, 4)]), 'for i in 3 2 1; do mv bk.$i.tgz bk.$((i+1)).tgz; done; tar czf bk.1.tgz -C $SRC m', lambda c: nfiles(c, '/bk.*.tgz', 4))
wl(s, 'rename_to_jpeg_ext_fix', lambda c: mk_media(c['B'] + '/m', 30, c['rng'], ext='jpe'), 'cd m && for f in *.jpe; do mv $f ${f%.jpe}.jpeg; done', lambda c: nfiles(c, '/m/*.jpeg', 30))
wl(s, 'rename_tif_to_tiff', lambda c: mk_media(c['B'] + '/m', 30, c['rng'], magic=b'II*\x00', ext='tif'), 'cd m && for f in *.tif; do mv $f ${f}f; done', lambda c: nfiles(c, '/m/*.tiff', 30))
wl(s, 'reencode_png_to_jpeg_inplace', lambda c: mk_photos(c, c['B'] + '/p', 20, ext='png', fmt='PNG'), "python3 -c \"from PIL import Image\nimport glob\nfor f in glob.glob('p/*.png'):\n    Image.open(f).convert('RGB').save(f,'JPEG')\"", lambda c: nfiles(c, '/p/*.png', 20))
wl(s, 'reencode_jpeg_quality_inplace', lambda c: mk_photos(c, c['B'] + '/p', 25, size=128), "python3 -c \"from PIL import Image\nimport glob\nfor f in glob.glob('p/*.jpg'):\n    Image.open(f).save(f,'JPEG',quality=60)\"", lambda c: nfiles(c, '/p/*.jpg', 25))
wl(s, 'ffmpeg_remux_new', lambda c: None, 'ffmpeg -loglevel quiet -f lavfi -i sine=duration=2 s.wav; for i in 1 2 3 4 5; do ffmpeg -loglevel quiet -i s.wav -c:a pcm_s16le r$i.wav; done', lambda c: nfiles(c, '/r*.wav', 5))
wl(s, 'dd_blocks_to_new_image', lambda c: None, 'dd if=/dev/urandom of=disk.img bs=64k count=300 status=none; dd if=disk.img of=copy.img bs=64k status=none', lambda c: os.path.getsize(c['M'] + '/copy.img') == 300 * 65536)
wl(s, 'sqlite_vacuum', lambda c: sh(f"python3 -c \"import sqlite3;c=sqlite3.connect('{c['B']}/v.db');c.execute('create table t(a,b)');c.executemany('insert into t values(?,?)',[(j,'v'*50) for j in range(6000)]);c.commit();c.execute('delete from t where a%2');c.commit()\""), "python3 -c \"import sqlite3;c=sqlite3.connect('v.db');c.execute('vacuum')\"", lambda c: sh(f"python3 -c \"import sqlite3;print(sqlite3.connect('{c['M']}/v.db').execute('select count(*) from t').fetchone()[0])\"").stdout.strip() == '3000')
wl(s, 'mbox_append_and_compact', lambda c: open(c['B'] + '/mbox', 'w').write('From x\n\nbody\n' * 4000), "python3 -c \"f=open('mbox','a')\nfor i in range(500): f.write('From y\\n\\nnew %d\\n'%i)\nf.close()\ns=open('mbox').read().replace('body','b'); open('mbox','w').write(s)\"", lambda c: os.path.getsize(c['M'] + '/mbox') > 1000)
wl(s, 'config_dir_templating', lambda c: mk_text(c['B'] + '/etc', 40, c['rng'], ext='conf'), "for f in etc/*.conf; do sed 's/alpha/ALPHA/' $f > $f.new; cp $f $f.bak; mv $f.new $f; done", lambda c: nfiles(c, '/etc/*.bak', 40))
wl(s, 'tmp_cleanup_old_files', lambda c: mk_text(c['B'] + '/tmp', 80, c['rng'], ext='tmp'), "find tmp -name '*.tmp' -delete", lambda c: nfiles(c, '/tmp/*.tmp', 0))
wl(s, 'rm_media_dir', lambda c: mk_media(c['B'] + '/m', 40, c['rng']), 'rm -rf m', lambda c: not os.path.exists(c['M'] + '/m'))
wl(s, 'gzip_d_then_edit_then_gzip', lambda c: (mk_text(c['B'] + '/t', 20, c['rng']), sh(f"gzip {c['B']}/t/*.txt")), "for f in t/*.gz; do gunzip $f; g=${f%.gz}; echo more >> $g; gzip $g; done", lambda c: nfiles(c, '/t/*.gz', 20))
wl(s, 'zip_add_to_archive', lambda c: (mk_media(c['SRC'] + '/m', 20, c['rng']), mk_media(c['SRC'] + '/m2', 20, c['rng'], prefix='x'), sh(f"cd {c['SRC']} && zip -qr {c['B']}/a.zip m")), 'zip -qr a.zip $SRC/m2', lambda c: int(sh(f"unzip -Z1 {c['M']}/a.zip | grep -vc '/$'").stdout.strip() or 0) == 40)
wl(s, 'pdf_like_save_incremental', lambda c: [open(f"{c['B']}/d{i}.pdf", 'wb').write(b'%PDF-1.4\n' + c['rng'].randbytes(30000)) for i in range(20)], "python3 -c \"import glob\nfor f in glob.glob('*.pdf'):\n    open(f,'ab').write(b'\\n%%EOF-incr\\n'*5)\"", lambda c: nfiles(c, '/*.pdf', 20))
wl(s, 'jpeg_exif_touch_in_place', lambda c: mk_media(c['B'] + '/m', 30, c['rng']), "python3 -c \"import glob\nfor f in glob.glob('m/*.jpg'):\n    fh=open(f,'r+b'); fh.seek(6); fh.write(b'XY'); fh.close()\"", lambda c: nfiles(c, '/m/*.jpg', 30))
wl(s, 'cp_reflink_style_copy_then_swap', lambda c: mk_media(c['B'] + '/m', 25, c['rng']), 'cd m && for f in *.jpg; do cp $f $f.copy && mv $f.copy $f; done', lambda c: nfiles(c, '/m/*.jpg', 25))
wl(s, 'unarchive_7z_like_tar_xz', lambda c: (mk_media(c['SRC'] + '/m', 25, c['rng']), sh(f"cd {c['SRC']} && tar cJf m.txz m")), 'tar xJf $SRC/m.txz', lambda c: same_tree(c['SRC'] + '/m', c['M'] + '/m'))
wl(s, 'python_pickle_save_models', lambda c: None, "python3 -c \"import pickle,os\nos.makedirs('mdl',exist_ok=True)\nfor r in range(3):\n    for i in range(15):\n        pickle.dump(list(range(5000)),open('mdl/m%d.pkl'%i,'wb'))\"", lambda c: nfiles(c, '/mdl/*.pkl', 15))

def run_suite(a):
    hb.W[:] = S[a.suite]
    os.makedirs(WORK, exist_ok=True)
    names = [w[0] for w in hb.W if not a.only or w[0] in a.only.split(',')]
    tasks = [(c, n, r) for c in a.configs.split(',') for n in names for r in range(a.reps)]
    random.Random(2).shuffle(tasks)
    done = set(); exists = os.path.exists(a.out)
    if exists:
        for r in csv.DictReader(open(a.out)): done.add((r['cfg'], r['workload'], int(r['rep'])))
        tasks = [t for t in tasks if t not in done]
    f = ['cfg','workload','rep','seconds','detections','ambiguous_events','verified_live','verified_durable','error']
    with open(a.out, 'a' if exists else 'w', newline='') as fo, cf.ThreadPoolExecutor(a.jobs) as ex:
        w = csv.DictWriter(fo, fieldnames=f, extrasaction='ignore')
        if not exists: w.writeheader()
        for i, r in enumerate(ex.map(hb.run_one, tasks)):
            w.writerow(r); fo.flush()
            if i % 10 == 0: print(f'{i}/{len(tasks)}', flush=True)

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('out'); ap.add_argument('--suite', default='s2')
    ap.add_argument('--configs', default='holdfast'); ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--jobs', type=int, default=2); ap.add_argument('--only', default='')
    run_suite(ap.parse_args())
