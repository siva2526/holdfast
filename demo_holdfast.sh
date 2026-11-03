#!/usr/bin/env bash
# demo_holdfast.sh -- five-act live demonstration of Holdfast with PASS/FAIL checks.
#   Act 1  benign work is NOT flagged        (tar, sed -i, bulk renames, cp)
#   Act 2  in-place ransomware is stopped    (files stay intact in the live view)
#   Act 3  replace-style ransomware (write temp, rename over original) is stopped
#   Act 4  a false positive is recoverable   (rrfs_ctl release)
#   Act 5  cooperating per-file processes    (alert + checkpoint, then rollback restores everything)
# Usage:  ./demo_holdfast.sh [--bin DIR] [--pause]      (--pause waits for Enter between acts, for presenting)
# Needs: a built tree (cmake + make), fuse3, python3. Exit code 0 = every check passed.
set -uo pipefail
set +m
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$ROOT/build"; PAUSE=0
while [ $# -gt 0 ]; do case "$1" in --bin) BIN="$2"; shift 2;; --pause) PAUSE=1; shift;; *) echo "unknown arg $1"; exit 2;; esac; done
[ -x "$BIN/rrfs_fuse" ] || { echo "rrfs_fuse not found in $BIN -- build first: mkdir -p build && cd build && cmake .. && make -j"; exit 2; }
command -v fusermount3 >/dev/null || { echo "fusermount3 not found (install fuse3)"; exit 2; }
W="$(mktemp -d /tmp/holdfast_demo_XXXXXX)"; PASS=0; FAIL=0; FPID=""
B=""; M=""
say()   { printf '\n\033[1m%s\033[0m\n' "$*"; }
note()  { printf '   \033[2m%s\033[0m\n' "$*"; }
check() { if [ "$1" = "0" ]; then printf '   \033[32mPASS\033[0m  %s\n' "$2"; PASS=$((PASS+1)); else printf '   \033[31mFAIL\033[0m  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }
pause() { [ "$PAUSE" = 1 ] && read -r -p "   [Enter to continue] " _; true; }
events() { local n; n=$(grep -c "\"type\":\"$1\"" "$B/.rrfs_state/events.log" 2>/dev/null); echo "${n:-0}"; }
stop_mount() { fusermount3 -uz "$M" >/dev/null 2>&1; [ -n "$FPID" ] && kill "$FPID" 2>/dev/null; FPID=""; sleep 0.3; }
trap 'stop_mount; echo; echo "(scratch files in $W)"' EXIT

fresh() {   # fresh mount with a 20-file corpus (text, jpeg-signature, zip-signature); sets B, M, and ORIG manifest
    stop_mount; B="$W/$1/backing"; M="$W/$1/mount"; mkdir -p "$B" "$M"
    python3 - "$B" <<'PY'
import os,sys,random,base64
b=sys.argv[1]; r=random.Random(7)
for i in range(1,21):
    raw=r.randbytes(r.randint(8000,40000)); k=i%3
    d=base64.encodebytes(raw) if k==0 else (b'\xff\xd8\xff\xe0'+raw if k==1 else b'PK\x03\x04'+raw)
    open(f'{b}/doc{i}.txt','wb').write(d)
PY
    ( cd "$B" && md5sum doc*.txt | sort -k2 ) > "$W/$1/manifest"
    printf 'baseline_interval_seconds = 0\nsuspend_on_detect = true\n' > "$B/rrfs.conf"
    setsid "$BIN/rrfs_fuse" "$B" "$M" -f >"$W/$1/fuse.log" 2>&1 & FPID=$!
    for _ in $(seq 60); do mountpoint -q "$M" && break; sleep 0.1; done
    mountpoint -q "$M" || { echo "mount failed:"; cat "$W/$1/fuse.log"; exit 1; }
}
live_intact() { ( cd "$M" && md5sum doc*.txt 2>/dev/null | sort -k2 ) | diff -q - "$W/$1/manifest" >/dev/null; }
store_intact() { ( cd "$B" && md5sum doc*.txt 2>/dev/null | sort -k2 ) | diff -q - "$W/$1/manifest" >/dev/null; }
wait_event() { for _ in $(seq $(( $2 * 10 ))); do [ "$(events "$1")" -gt 0 ] && return 0; sleep 0.1; done; return 1; }
endatk() { kill -9 -- -"$ATK" 2>/dev/null; kill -9 "$ATK" 2>/dev/null; wait "$ATK" 2>/dev/null; true; }
attack() {  # run a python attacker through a disposable sh so the daemon's parent-bucket SIGSTOP never hits this script
    cd "$M" || exit 1
    setsid sh -c 'python3 -c "$0"; true' "$1" >/dev/null 2>&1 &
    ATK=$!
    cd "$ROOT" || exit 1
}

say "Holdfast demo  (work dir: $W)"
note "Holdfast = FUSE3 filesystem that holds destructive writes back, scores each process, and freezes ransomware-like ones."
pause

# ------------------------------------------------------------------ Act 1
say "ACT 1 - Benign work must not be flagged"
fresh act1
( cd "$M" && tar czf backup.tgz doc*.txt && mkdir -p notes && for i in 1 2 3 4 5 6 7 8 9 10; do echo "meeting $i alpha" > notes/n$i.txt; done \
  && sed -i 's/alpha/ALPHA/' notes/n*.txt && cd notes && for f in n*.txt; do mv "$f" "${f%.txt}.md"; done && cd .. && cp -r notes notes_copy ) 
sleep 3
note "tar, sed -i, a shell loop renaming .txt -> .md, and cp -r were run through the mount."
check "$([ "$(events detect)" = 0 ] && echo 0 || echo 1)" "no detection raised ($(events detect) detect events)"
check "$([ "$(grep -c ALPHA "$M"/notes_copy/n1.md)" = 1 ] && echo 0 || echo 1)" "edited and copied files have the expected content"
pause

# ------------------------------------------------------------------ Act 2
say "ACT 2 - In-place ransomware overwrites every file with random bytes"
fresh act2
attack 'import os
for f in sorted(x for x in os.listdir(".") if x.startswith("doc")):
    fd=os.open(f,os.O_WRONLY); os.pwrite(fd,os.urandom(os.path.getsize(f)),0); os.close(fd)'
wait_event detect 15
sleep 0.5
note "$(grep '"type":"detect"' "$B/.rrfs_state/events.log" | head -1 | cut -c1-150)"
check "$([ "$(events detect)" -ge 1 ] && echo 0 || echo 1)" "ransomware detected and frozen (SIGSTOP)"
check "$(live_intact act2 && echo 0 || echo 1)" "all 20 originals byte-identical in the live view at the moment of detection"
check "$(store_intact act2 && echo 0 || echo 1)" "all 20 originals byte-identical in the backing store (attack was held back)"
endatk
pause

# ------------------------------------------------------------------ Act 3
say "ACT 3 - Replace-style ransomware: write ciphertext to a temp file, rename over the original"
fresh act3
attack 'import os
for f in sorted(x for x in os.listdir(".") if x.startswith("doc")):
    n=os.path.getsize(f); open(f+".tmp","wb").write(os.urandom(n)); os.rename(f+".tmp",f)'
wait_event detect 15; sleep 0.5
check "$([ "$(events detect)" -ge 1 ] && echo 0 || echo 1)" "replace-style ransomware detected and frozen"
INT=$( cd "$M" && md5sum doc*.txt 2>/dev/null | sort -k2 | diff - "$W/act3/manifest" | grep -c '^<' )
note "files already replaced before the freeze: $INT of 20 (the rest were never touched)"
CK=$("$BIN/rrfs_ctl" "$M" checkpoints 2>/dev/null | awk '/ckpt_/{print $1; exit}')
"$BIN/rrfs_ctl" "$M" rollback "$CK" >/dev/null 2>&1; sleep 0.5
check "$(store_intact act3 && echo 0 || echo 1)" "after 'rrfs_ctl rollback' every original is restored byte-for-byte"
endatk
pause

# ------------------------------------------------------------------ Act 4
say "ACT 4 - A legitimate job that LOOKS like ransomware gets frozen; the operator releases it"
fresh act4
attack 'import os
for f in sorted(x for x in os.listdir(".") if x.startswith("doc")):
    n=os.path.getsize(f); open(f,"wb").write(os.urandom(n))   # e.g. a legitimate re-encryption job
open("done.flag","w").write("1")'
wait_event detect 15; sleep 0.5
PIDX=$(grep '"type":"detect"' "$B/.rrfs_state/events.log" | head -1 | sed 's/.*"pid":\([0-9]*\).*/\1/')
ST=$(awk '{print $3}' /proc/"$PIDX"/stat 2>/dev/null || echo gone)
note "process $PIDX state: $ST (T = stopped)"
check "$([ "$ST" = T ] && echo 0 || echo 1)" "job was frozen while its writes are held back and hidden"
check "$(live_intact act4 && echo 0 || echo 1)" "originals still intact for every other reader"
"$BIN/rrfs_ctl" "$M" release "$PIDX" | head -1
sleep 2
ST2=$(awk '{print $3}' /proc/"$PIDX"/stat 2>/dev/null || echo gone)
note "after release, process state: $ST2"
check "$([ "$ST2" != T ] && echo 0 || echo 1)" "operator release resumed the job (a false positive costs a stop, not data)"
endatk
pause

# ------------------------------------------------------------------ Act 5
say "ACT 5 - Evasion: one short-lived, detached process per file (no common parent)"
fresh act5
attack 'import os,time
for f in sorted(x for x in os.listdir(".") if x.startswith("doc")):
    pid=os.fork()
    if pid==0:
        os.setsid()
        if os.fork()==0:
            n=os.path.getsize(f); open(f+".tmp","wb").write(os.urandom(n)); os.rename(f+".tmp",f); os._exit(0)
        os._exit(0)
    os.waitpid(pid,0); time.sleep(0.05)'
wait_event cluster 15; sleep 2
note "$(grep '"type":"cluster"' "$B/.rrfs_state/events.log" | head -1 | cut -c1-170)"
check "$([ "$(events cluster)" -ge 1 ] && echo 0 || echo 1)" "cooperation alert raised (nobody frozen: this tier only holds commits and takes a checkpoint)"
CK=$("$BIN/rrfs_ctl" "$M" checkpoints 2>/dev/null | awk '/ckpt_/{print $1; exit}')
"$BIN/rrfs_ctl" "$M" rollback "$CK" >/dev/null 2>&1; sleep 0.5
check "$(store_intact act5 && echo 0 || echo 1)" "rollback to the alert's checkpoint restores all 20 originals"
endatk

say "Summary: $PASS passed, $FAIL failed"
note "Known limits (be upfront): unknown-format data already near 8 bits/byte is only deferred, not frozen; Act 5 is recovery, not prevention."
[ "$FAIL" = 0 ]
