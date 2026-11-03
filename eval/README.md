# Evaluation harness and data

Everything in the paper's evaluation (Sec. 5) comes from the scripts and data here. Python 3 (with Pillow for a few image
workloads) and a working FUSE mount are needed; build the daemon first (`cmake -S .. -B ../build && cmake --build ../build`).
Always run with `PYTHONHASHSEED=0` (the run scripts do). Scratch space is `$HF_WORK` (default `/tmp/hf_work`); the daemon
binaries are taken from `$HF_BIN` (default `../build`).

| File | Purpose |
|---|---|
| `hf_lib.py` | mount lifecycle, corpora, metrics, and the **presets**: `holdfast`, `prov` (strict mode), `restore_only`, `redirect_only` (re-implementations of the *decision principle* of ShieldFS and Redemption inside this code base), `fast`, and ablations |
| `hf_attack.py` | attack matrix: 14 wiper styles + 5 read-encrypt-write styles, `mixed` and `unknown` corpora |
| `hf_benign.py`, `hf_benign2.py`, `hf_benign4.py` | benign suites S1 (24 workloads), S2 (37), S3 (25), S4 (24) run with real tools |
| `hf_benign5.py` | S5: adversarial look-alikes for the read-provenance signal |
| `hf_adaptive.py` | 40 randomized attackers per corpus (workers, pacing, chunking, coverage, spawn style) |
| `hf_bound.py` | paced attackers against the damage-rate bound |
| `hf_blind.py`, `hf_ringwindow.py` | recovery when no detection or alert fired (`promote recover` + `rollback`); ring-window variant |
| `hf_release_test.py` | release undoes the repair; shelved writes survive `kill -9` |
| `expL_crash_durability.sh`, `expM_overhead.sh`, `expO_fastcopy.sh` | durability window, overhead micro-benchmarks, fast-copy comparison (`lib.sh` is shared) |
| `run_evaluation.sh` | the whole evaluation, resumable (`.ok` markers); many hours on 2 vCPUs, run it as a background job |
| `run_fast_copy_regression.sh` | re-runs the attack matrix and S1-S4 with `holdback_fast_copy = true` |
| `CODE_FREEZE_SHA256_*.txt` | source hashes (see below) |
| `results/final/` | attack matrix, S1-S5, adaptive search, release test, rate-bound test (CSV/JSON) |
| `results/blind/`, `results/fast/` | recovery-without-detection test; fast-copy regression |
| `results/overhead.txt`, `results/crash_durability.txt` | output of `expM_overhead.sh`, `expL_crash_durability.sh` |

A quick smoke test (about a minute): `PYTHONHASHSEED=0 python3 hf_attack.py /tmp/smoke.csv --configs holdfast --corpora mixed --attacks inplace_full,rw_inplace --trials 1`.

## Source hashes

The main evaluation ran on the source in `CODE_FREEZE_SHA256_final.txt`. The shipped source differs from it in three files
(`include/holdback.hpp`, `src/holdback.cpp`, `src/rrfs_fuse.cpp`, listed in `CODE_FREEZE_SHA256_final2.txt`) by the opt-in,
default-off `holdback_fast_copy` path, whose regression run (`results/fast/`) gave identical decisions. The final repository
differs from `final2` only in comments (version tags removed): the stripped `rrfs_fuse` and `rrfs_ctl` binaries are
byte-identical. `CODE_FREEZE_SHA256_release.txt` is the hash of this repository's `src/` and `include/`.

Measurements are from a 2-vCPU VM and are not portable: the CSV rows are what the paper's tables were computed from.
