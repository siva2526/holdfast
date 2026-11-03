#!/usr/bin/env bash
# install.sh -- one command from a fresh Ubuntu/Debian/Fedora box or WSL2 shell to a built, tested Holdfast.
#   ./install.sh            install dependencies (needs sudo), build, run the unit tests, print next steps
#   ./install.sh --check    only report what is missing (changes nothing)
set -uo pipefail
cd "$(dirname "$0")"
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1
ok()   { printf '  [ok]   %s\n' "$1"; }
miss() { printf '  [MISS] %s  ->  %s\n' "$1" "$2"; MISSING=1; }
MISSING=0
report() {
  MISSING=0
  command -v cmake >/dev/null && ok cmake || miss cmake "install cmake"
  command -v g++ >/dev/null && ok g++ || miss g++ "install build-essential"
  pkg-config --exists fuse3 2>/dev/null && ok "libfuse3 headers ($(pkg-config --modversion fuse3))" || miss "libfuse3-dev" "apt install libfuse3-dev"
  command -v fusermount3 >/dev/null && ok fusermount3 || miss fusermount3 "apt install fuse3"
  [ -e /dev/fuse ] && ok /dev/fuse || miss /dev/fuse "WSL2: run 'wsl --update' in PowerShell, then 'wsl --shutdown' and reopen"
  command -v python3 >/dev/null && ok python3 || miss python3 "apt install python3"
  python3 -c 'import PIL' 2>/dev/null && ok "python3 PIL (only for the extra benign test suites)" || printf '  [info] python3-pillow not installed (optional: only the evaluation harness needs it)\n'
}
echo "== Holdfast: environment =="; report
if [ $CHECK = 1 ]; then exit $MISSING; fi
if [ $MISSING = 1 ]; then
  echo "== installing dependencies =="
  if command -v apt-get >/dev/null; then
    sudo apt-get update && sudo apt-get install -y build-essential cmake pkg-config libfuse3-dev fuse3 python3 python3-pil rsync zip unzip
  elif command -v dnf >/dev/null; then
    sudo dnf install -y gcc-c++ cmake pkgconf-pkg-config fuse3-devel fuse3 python3 python3-pillow rsync zip unzip
  else
    echo "No apt-get or dnf found: install cmake, a C++17 compiler, libfuse3 development files and fuse3 by hand."; exit 1
  fi
  echo "== re-checking =="; report
  [ -e /dev/fuse ] || { echo "/dev/fuse is still missing; fix that first (see above), then re-run."; exit 1; }
fi
echo "== building =="
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build -j"$(nproc)" 2>&1 | tail -2 || exit 1
echo "== unit tests =="
(cd build && ctest 2>&1 | tail -4)
cat <<TXT

Done. Next:
  ./start_panel.sh        visual demo panel in your browser (recommended for presenting)
  ./demo_holdfast.sh      scripted five-act terminal demo with 12 pass/fail checks
TXT
