# Shared helpers for the shell experiments. Needs a built ../build.
AUDIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$AUDIT_DIR/.." && pwd)"
BIN="$ROOT/build"
WORK="${HOLDFAST_EVAL_WORK:-/tmp/holdfast_eval}"; mkdir -p "$WORK"; chmod 755 "$WORK"
start_mount() { # $1=name  $2=optional sed expr applied to the copy of rrfs.conf
  W=$WORK/$1; B=$W/backing; M=$W/mount; rm -rf $W; mkdir -p $B $M
  cp "$ROOT/rrfs.conf.example" $B/rrfs.conf
  [ -n "${2:-}" ] && sed -i "$2" $B/rrfs.conf
  ( setsid $BIN/rrfs_fuse $B $M -f </dev/null >$W/fuse.log 2>&1 & )
  for i in $(seq 1 30); do mountpoint -q $M && break; sleep 0.2; done
  mountpoint -q $M || { echo "MOUNT FAILED"; cat $W/fuse.log; return 1; }
}
stop_mount() { fusermount3 -uz $M 2>/dev/null; sleep 0.3; }
state() { ps -o stat= -p "$1" 2>/dev/null | tr -d ' ' | cut -c1; }
