#!/bin/bash
# Two-sided durability experiment for hold-back (kill -9 of the daemon):
#  (1) mid-ATTACK crash: how many originals are intact in the BACKING store?
#  (2) mid-BENIGN-EDIT crash: is an acknowledged user edit still on disk?
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
attack_crash() { # $1 name  $2 sed
  start_mount "$1" "$2" || return
  for i in $(seq 1 12); do printf 'HEADER-%d ' $i > $B/f$i.dat; head -c 6000 /dev/zero | tr '\0' 'A' >> $B/f$i.dat; done; sleep 1.5
  ( cd $M; timeout 20 python3 -c "
import os,time
for i in range(1,13):
    fd=os.open('f%d.dat'%i,os.O_WRONLY); os.pwrite(fd,os.urandom(6010),0); os.close(fd); time.sleep(0.12)
" >/dev/null 2>&1 & echo $! > $W/p ); sleep ${CRASH_AT:-0.55}
  pkill -9 -x rrfs_fuse; sleep 0.3
  n=0; for i in $(seq 1 12); do head -c 12 $B/f$i.dat | grep -q "HEADER-$i " && n=$((n+1)); done
  echo "  $1: attacker killed-daemon mid-attack -> originals intact in BACKING: $n/12"
  kill -9 $(cat $W/p) 2>/dev/null; fusermount3 -uz $M 2>/dev/null; sleep 0.3
}
edit_crash() {
  start_mount "$1" "$2" || return
  echo "version 1" > $B/note.txt; sleep 1.2
  echo "version 2 (user edit)" > $M/note.txt; sleep 0.5      # acknowledged to the app, then the daemon dies
  pkill -9 -x rrfs_fuse; sleep 0.3
  echo "  $1: benign edit acknowledged, daemon killed 0.5 s later -> on disk: '$(cat $B/note.txt)'"
  fusermount3 -uz $M 2>/dev/null; sleep 0.3
}
echo "## attack, daemon crash mid-attack"
attack_crash with_holdback ''
attack_crash no_holdback '$a holdback_enabled = false'
echo "## benign edit, daemon crash within the commit window"
edit_crash with_holdback ''
edit_crash no_holdback '$a holdback_enabled = false'
