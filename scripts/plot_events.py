#!/usr/bin/env python3
"""
plot_events.py -- turn rrfs's JSONL event log into a score-over-time
chart: one line per writing process, with detection, suspend, promote,
and rollback events marked. Useful as a report figure or a live-demo
screenshot -- this is the same kind of measurement your literature
review cites from van Sloun et al. (NDSS 2025) for detector overhead
and latency analysis.

Usage:
    python3 scripts/plot_events.py <events.log> [output.png]

Example:
    python3 scripts/plot_events.py /tmp/rrfs_demo_XXXX/backing/.rrfs_state/events.log
"""
import json
import sys
from collections import defaultdict


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <events.log> [output.png]", file=sys.stderr)
        sys.exit(1)

    log_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "rrfs_score_timeline.png"

    try:
        import matplotlib
        matplotlib.use("Agg")  # headless-safe: no display needed (WSL-friendly)
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed. Install it with one of:")
        print("  pip3 install matplotlib --break-system-packages")
        print("  pip3 install --user matplotlib")
        sys.exit(2)

    series = defaultdict(list)   # pid -> [(t_seconds, score), ...]
    detect_events = []           # (t, pid, score)
    suspend_events = []          # (t, pid, score)
    promote_events = []          # (t, checkpoint_id)
    rollback_events = []         # (t, checkpoint_id)

    t0 = None
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = ev.get("ts")
            if ts is None:
                continue
            if t0 is None:
                t0 = ts
            t = (ts - t0) / 1000.0  # seconds since first logged event

            etype = ev.get("type")
            pid = ev.get("pid", -1)
            score = ev.get("score")

            if etype == "write" and score is not None and pid is not None and pid >= 0:
                series[pid].append((t, score))
            elif etype == "detect":
                detect_events.append((t, pid, score))
            elif etype == "suspend":
                suspend_events.append((t, pid, score))
            elif etype == "promote":
                promote_events.append((t, ev.get("checkpoint_id", "")))
            elif etype == "rollback":
                rollback_events.append((t, ev.get("checkpoint_id", "")))

    if not series and not detect_events:
        print("No write/detect events found in the log -- nothing to plot.")
        sys.exit(0)

    fig, ax = plt.subplots(figsize=(10, 6))

    for pid, points in series.items():
        points.sort()
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        ax.plot(xs, ys, marker="o", markersize=3, linewidth=1.5, label=f"pid {pid}")

    for t, pid, score in detect_events:
        ax.axvline(t, color="red", linestyle="--", alpha=0.5)
        ax.annotate(f"detect (pid {pid})", (t, score if score else 0),
                    textcoords="offset points", xytext=(5, 10),
                    fontsize=8, color="red")

    for t, pid, score in suspend_events:
        ax.scatter([t], [score if score else 0], color="black", marker="x",
                   s=90, zorder=5, label="_nolegend_")

    for t, ckpt in promote_events:
        ax.axvline(t, color="green", linestyle=":", alpha=0.4)

    for t, ckpt in rollback_events:
        ax.axvline(t, color="blue", linestyle="-.", alpha=0.6)
        ax.annotate("rollback", (t, 0), textcoords="offset points",
                    xytext=(5, -15), fontsize=8, color="blue")

    ax.set_xlabel("seconds since first logged event")
    ax.set_ylabel("composite anomaly score")
    ax.set_title("rrfs: per-process anomaly score over time\n"
                  "(red dashed = detect, black x = suspend, green dotted = checkpoint, "
                  "blue dash-dot = rollback)")
    if series:
        ax.legend(loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
