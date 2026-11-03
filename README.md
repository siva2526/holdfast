# Holdfast

Holdfast is a ransomware-resistant filesystem for Linux, written in C++17 on FUSE3. It sits on top of an ordinary
directory (the *backing directory*) and watches every write that goes through the mount. It keeps the original bytes of
anything that gets overwritten, truncated, renamed or deleted, holds back writes from processes that look suspicious,
freezes a process that is destroying content, and can restore the originals afterwards.

It is also a testbed: the two published decision principles, **restore-after-detect** (ShieldFS, ACSAC 2016) and
**hold-before-commit** (Redemption, RAID 2017), are implemented as configuration presets next to Holdfast's own hybrid,
so they can be compared in one code base against the same attackers and the same benign workloads.

> **Status: research prototype.** Evaluated only with synthetic attackers on one virtual machine; no real ransomware.
> Not tamper-resistant against root. The binaries keep the working names `rrfs_fuse` (daemon) and `rrfs_ctl` (operator tool).

The accompanying paper is built from [`paper/`](paper/) (`python3 paper/build_paper.py --url <this repository URL>`); read its limitations before relying on or citing any number here.

## What is new here

Write redirection with a verdict-based commit is Redemption's idea and shadow copy plus restore is ShieldFS's; Holdfast does
not claim either. The parts that are Holdfast's own:

1. **Read provenance** (opt-in, `read_provenance = true`). Overwriting noise with ciphertext shows no entropy rise and no
   destroyed signature, so content tests cannot tell encryption from a benign re-sync. The daemon remembers which files a
   process read through the mount; an in-place overwrite of a high-entropy original by unrelated high-entropy bytes, by a
   process (or its parent) that read that file, counts as destroyed content. Read-encrypt-write attackers on unknown-format
   data went from 6 of 30 trials frozen to 30 of 30, with 0 of 110 benign workloads frozen. Cost: tools that hash or compare a
   file and then overwrite it with new noise-like data (rsync `--checksum`, compare-then-copy, vault re-encryption) are frozen
   too (4 of 10 adversarial look-alikes). Wipers that never read their targets are not covered.
2. **Recovery that does not depend on detection.** A copy-on-write ring keeps the original bytes; flagged writes are
   *shelved* (hidden, kept) so a false positive can be released; soft alerts take checkpoints rebuilt from the ring;
   `rrfs_ctl promote recover` then `rollback` restored every original in all 96 trials of an evasion test, including 42 trials
   in which nothing was detected and no alert was raised. How long originals stay recoverable was not bounded.
3. **A reliability-first response model**: a freeze needs content evidence on at least two files; rename-only activity only
   alerts; ambiguous noise-over-noise overwrites are deferred (default 30 s) and checkpointed; a cooperation-aware hold tier
   covers attackers split over unrelated processes.
4. **A hybrid design**: hold-back for overwrites and truncations, an undo journal with quarantine for replace, delete and
   rename, a slow-burn signal, and process-tree aggregation.

## Results at a glance

All numbers come from the data in [`eval/results/`](eval/results/); see the paper for method, caveats and confidence intervals.

| | restore-only | redirect-only | Holdfast | Holdfast strict |
|---|---|---|---|---|
| Benign workloads frozen (S1-S4, 110) | 15 | 8 | **0** | **0** |
| Attacks frozen with 100% of files intact (19 styles, mixed corpus) | 0 | 9 | **16** | **16** |
| Read-encrypt-write attackers frozen, unknown-format data (30 trials) | 24 | 6 | 6 | **30** |

Restore-only freezes noise-over-noise attacks only because it scores entropy alone, which is also why it has the most false positives; it lets the damage land first (59% to 94% of files intact at the freeze). The other three attack styles on recognizable formats (rename-only, copy-out-and-delete, a double-forked process per file)
raise an alert only; rolling back to the alert checkpoint restored every original in 18 of 18 trials. On unknown-format data
the default build defers and alerts rather than freezing (adaptive search: 67% loss without action, 40% after rollback).
Hold-back is slow on a 2-vCPU VM (overwriting 1,000 small files: 0.80 s with hold-back, 0.22 s without, 0.08 s direct), and an
edit acknowledged 0.5 s before a daemon crash is lost.

## Build and run

Needs Linux (or WSL2) with FUSE3, CMake and a C++17 compiler.

```sh
./install.sh                 # installs dependencies (sudo), builds, runs the unit tests  (./install.sh --check only reports)
# or by hand:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && ctest --test-dir build   # 11 suites

mkdir -p /tmp/backing /tmp/mount
cp rrfs.conf.example /tmp/backing/rrfs.conf              # optional; every key is documented in the file
./build/rrfs_fuse /tmp/backing /tmp/mount -f &           # state lives in /tmp/backing/.rrfs_state
./build/rrfs_ctl /tmp/mount status
fusermount3 -u /tmp/mount
```

Demos: `./start_panel.sh` opens a browser panel (setup, attackers, benign look-alikes, live events, release/rollback);
`./demo_holdfast.sh` runs a five-act terminal demo with 12 pass/fail checks. Both use synthetic attackers on files they create.

### Operator commands

| Command | Effect |
|---|---|
| `rrfs_ctl <mnt> status` / `checkpoints` / `watch` | state, checkpoints, recent events |
| `release <pid>` | false-positive override: commits the pid's shelved writes, puts back the namespace changes the repair reverted (restored versions kept in `.rrfs_state/undo/`), resumes the pid and its parent. Works after a daemon restart (`shelf.manifest`) |
| `discard <pid>` / `discard cluster` | drop shelved or cluster-held writes |
| `promote [recover]` | take a checkpoint now; `recover` rebuilds it from the original-byte ring |
| `diff <ckpt>` / `rollback <ckpt>` | show / apply a restore (atomic renames) |
| `resume <pid>` | SIGCONT a process the daemon stopped |

### Configuration

`rrfs.conf` in the backing directory; copy `rrfs.conf.example`, which documents every key (thresholds, hold-back limits,
graded response, ambiguity policy, cluster tier, soft alerts, `read_provenance`, `holdback_fast_copy`, ...). Restart the
daemon to apply changes. The evaluation presets (restore-only, redirect-only, ...) are plain key overrides in
[`eval/hf_lib.py`](eval/hf_lib.py).

## How it works, briefly

Each mutating call passes a blocked-key gate, a copy-on-write step that preserves the bytes about to change, the anomaly
engine, and the hold-back overlay. Each process (and its parent) has a decaying additive score fed by bias-corrected entropy,
content delta against the preserved original, bursts of distinct files, extension churn and a slow-burn counter. A
threshold crossing with content evidence on two files freezes the process (SIGSTOP), discards or shelves its held writes,
and repairs the namespace (nothing is deleted; created files go to `.rrfs_state/quarantine/`). A damage-rate bound,
7 distinct content-evidence files per 300 s per process key, applies to attackers whose writes carry content evidence.
Details and the exact rules are in Sec. 3 of the paper.

## Limitations

- User-space filesystem: root, or any process that can write the backing directory directly, bypasses it. Run the daemon
  as a dedicated user with a `0700` backing directory to narrow the gap (not evaluated). The control channel refuses
  callers other than the daemon's uid and root.
- Whole-file hold-back (files over 64 MB are written in place with copy-on-write only); FUSE and hold-back overhead is large.
- Unknown-format data is deferred and alerted, not frozen, by default. Not frozen by any configuration: copy-out-and-delete,
  one detached process per file, entropy-capped encoding on unknown-format data (these alert or are recoverable, see paper).
- Recovery commands are run by an operator or a script; a deployment needs an alert channel and someone to act before the
  copy-on-write ring is pruned (`ring_size` generations; the window was not characterized).
- Evaluation: synthetic attackers written by the author, baselines are re-implementations of each *principle* (not
  ShieldFS or Redemption themselves), one VM, 6 trials per attack cell, benign suites written by the author with some rules
  refined after seeing failures on them. Zero false positives cannot be guaranteed.

## Repository layout

| Path | Contents |
|---|---|
| `src/`, `include/` | daemon (`rrfs_fuse.cpp`), operator tool (`rrfs_ctl.cpp`), anomaly engine, canary (copy-on-write) manager, hold-back overlay, extension tracker, event log |
| `tests/` | 11 CTest suites (no FUSE mount needed); `tests/stress/` ThreadSanitizer stress programs |
| `scripts/` | browser demo panel, synthetic attackers for demos, event plotting |
| `eval/` | evaluation harness, run scripts, and the data behind the paper (`eval/results/`); see [`eval/README.md`](eval/README.md) |
| `paper/` | the script that builds the paper from `eval/results/` (add the PDF here once published) |
| `docs/` | demo guide and architecture diagram |

## Citation and license

If you use this work, please cite the accompanying paper. Released under the MIT License (see `LICENSE`).
