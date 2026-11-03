#!/usr/bin/env bash
# start_panel.sh -- one command: build if needed, then open the visual Holdfast demo panel in your browser.
# Usage: ./start_panel.sh [port]     (default 8765; Ctrl-C stops the panel and unmounts)
set -e
cd "$(dirname "$0")"
if [ ! -x build/rrfs_fuse ]; then cmake -S . -B build >/dev/null && cmake --build build -j"$(nproc)"; fi
PORT="${1:-8765}"
( sleep 1; (command -v xdg-open >/dev/null && xdg-open "http://127.0.0.1:$PORT") || (command -v wslview >/dev/null && wslview "http://127.0.0.1:$PORT") || true ) >/dev/null 2>&1 &
exec python3 scripts/holdfast_panel.py --port "$PORT"
