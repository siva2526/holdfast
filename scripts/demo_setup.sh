#!/usr/bin/env bash
# demo_setup.sh -- prepare a manual demo: creates a 20-file corpus, mounts Holdfast, prints the commands to run next.
# Usage: scripts/demo_setup.sh [BIN_DIR]      (default ../build). Undo with: fusermount3 -u <mount>
BIN="${1:-$(cd "$(dirname "$0")/.." && pwd)/build}"; D="${HOLDFAST_DEMO_DIR:-$HOME/holdfast_demo}"
fusermount3 -uz "$D/mount" 2>/dev/null; rm -rf "$D"; mkdir -p "$D/backing" "$D/mount"
python3 - "$D/backing" <<'PY'
import os,sys,random,base64
b=sys.argv[1]; r=random.Random(7)
for i in range(1,21):
    raw=r.randbytes(r.randint(8000,40000)); k=i%3
    open(f'{b}/doc{i}.txt','wb').write(base64.encodebytes(raw) if k==0 else (b'\xff\xd8\xff\xe0'+raw if k==1 else b'PK\x03\x04'+raw))
PY
( cd "$D/backing" && md5sum doc*.txt | sort -k2 > "$D/manifest" )
printf 'baseline_interval_seconds = 0\nsuspend_on_detect = true\n' > "$D/backing/rrfs.conf"
setsid "$BIN/rrfs_fuse" "$D/backing" "$D/mount" -f > "$D/fuse.log" 2>&1 &
for _ in $(seq 60); do mountpoint -q "$D/mount" && break; sleep 0.1; done
mountpoint -q "$D/mount" || { echo "mount failed"; cat "$D/fuse.log"; exit 1; }
S="$(cd "$(dirname "$0")" && pwd)"
cat <<TXT
Holdfast is mounted.  backing=$D/backing   mount=$D/mount

Terminal 2 (live events):   python3 $S/live_events.py $D/backing
Terminal 3 (the attack):    cd $D/mount && sh -c 'python3 $S/attacker.py inplace; true'      # or: replace | perfile | benign-reencrypt
Check originals intact:     cd $D/mount && md5sum doc*.txt | sort -k2 | diff - $D/manifest && echo INTACT
Operator commands:          $BIN/rrfs_ctl $D/mount status | checkpoints | release <pid> | rollback <ckpt>
TXT
