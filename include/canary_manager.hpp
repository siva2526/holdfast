#pragma once
#include <chrono>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Implements the "Canary Snapshot Coordinator" from the proposal
// (Slide 15, Gap 2 + Gap 3):
//
//  - Gap 2 (proactive vs. reactive timing): `protect_before_write()` is
//    called on EVERY first-touch-per-generation write, unconditionally,
//    before the write is allowed to land. The canary buffer therefore
//    exists continuously, independent of whether the AnomalyEngine has
//    fired yet -- it does not wait for a detection event.
//
//  - Gap 3 (kernel-native/atomic recovery): `rollback()` restores state
//    via directory rename(2), which is atomic on a POSIX filesystem
//    when source and destination share the same mount. There is no
//    window where the tree is half-old/half-new.
//
// Note (two design points):
//  1. Automatic checkpoints (reason == "auto") are now RECONSTRUCTED
//     from the canary generations rather than being a plain copy of
//     the live tree. Previously an automatic checkpoint captured the
//     live tree *at detection time*, which already contained whatever
//     damage had landed -- the proactive copy-on-write data existed
//     on disk but nothing ever read it back. Now, for each path that
//     has a preserved canary copy, the OLDEST available generation's
//     copy is used (closest to pre-attack content, including under a
//     file's ORIGINAL name even if the attacker has since renamed the
//     live file away); paths with no canary copy fall back to the
//     live file. See promote_checkpoint() and
//     build_auto_checkpoint_locked().
//  2. protect_before_write() is now also called on a rename's
//     DESTINATION path (by the FUSE layer, see rrfs_fuse.cpp), not
//     only the source -- a "write ciphertext to a new file, then
//     rename it over the original" attack used to leave zero canary
//     copies of the victim.
//
// This is a userspace (FUSE) approximation of the proposal's intended
// VFS-level/kernel-resident design -- suitable for prototyping and
// demonstrating the architecture and for measuring overhead, but it
// does not have the tamper-resistance an in-kernel or block-layer
// implementation would have against a privileged attacker (this
// limitation is exactly Gap 3 in your own literature review, and is
// tracked explicitly in AUDIT_REPORT.pdf / README's limitations
// section rather than claimed as solved).
class CanaryManager {
public:
    struct CheckpointInfo {
        std::string id;
        long long timestamp_ms = 0;
        std::string reason;       // "manual" | "auto" | "scheduled"
        long trigger_pid = -1;    // -1 if not applicable (manual/scheduled)
        double trigger_score = -1.0;
    };

    struct DiffResult {
        std::vector<std::string> added;      // present live, not in checkpoint
        std::vector<std::string> removed;    // present in checkpoint, not live
        std::vector<std::string> modified;   // present in both, content differs
        std::vector<std::string> unchanged;  // present in both, identical content
    };

    CanaryManager(std::string backing_root, std::string canary_root,
                  std::string checkpoint_root, int ring_size = 8);

    void init();

    // Copy-on-write: preserves the pre-write bytes of `rel_path` into
    // the CURRENT canary generation, the first time this generation
    // sees a write to that path. No-op on subsequent writes to the
    // same path within the same generation, and a safe no-op (never
    // throws) if the source file cannot be read -- a snapshot system
    // degrading gracefully on one unreadable file is far preferable
    // to it aborting the whole daemon.
    void protect_before_write(const std::string& rel_path);

    // Freezes the current canary generation into a new, read-only
    // checkpoint directory (named by timestamp) and starts a fresh
    // generation. `reason`/`trigger_pid`/`trigger_score` are recorded
    // in a meta.json alongside the checkpoint for later inspection
    // (`rrfs_ctl <mount> checkpoints`). When `reason == "auto"`, the
    // checkpoint content is reconstructed preferring canary copies
    // over live content (see class comment, point 1). Returns the
    // checkpoint id, or an EMPTY STRING if the call was rejected by
    // the rate limiter (see set_min_promote_interval_ms) -- callers
    // must check for this rather than assuming success.
    std::string promote_checkpoint(const std::string& reason = "manual",
                                    long trigger_pid = -1, double trigger_score = -1.0);

    // Rejects promote_checkpoint() calls that arrive less than this
    // many milliseconds after the previous successful one (default 0
    // = unlimited, so existing tests that promote back-to-back are
    // unaffected). Bounds disk usage and duplicate full-tree copies
    // against a flood of PROMOTE commands through the control
    // channel (an audited attack: 15 anonymous commands created 15
    // full-tree copies with no cooldown).
    void set_min_promote_interval_ms(long ms);

    // Atomic, all-or-nothing restore of the backing tree to the state
    // captured in `checkpoint_id`. Returns false if the checkpoint
    // does not exist.
    bool rollback(const std::string& checkpoint_id);

    // Retention: keep at most `n` checkpoints whose reason is
    // "scheduled" (oldest are deleted first). 0 = unlimited. "manual"
    // and "auto" checkpoints are NEVER pruned automatically -- they are
    // the ones an operator or a detection event deliberately created.
    // Bounds the disk growth of periodic full-tree baselines.
    void set_max_scheduled_checkpoints(int n) { max_scheduled_ = n; }

    std::vector<CheckpointInfo> list_checkpoints() const;

    // Compares the LIVE backing tree against a checkpoint without
    // touching either -- read-only. Lets an operator (or rrfs_ctl diff)
    // see exactly what a rollback would change before committing to
    // it, which matters because rollback discards anything written
    // after the checkpoint. Returns an empty DiffResult (all vectors
    // empty) if the checkpoint doesn't exist; check with
    // list_checkpoints() first if that distinction matters.
    DiffResult diff_against(const std::string& checkpoint_id) const;

    // Renders a DiffResult as a human-readable report, used by both
    // the FUSE control-file interface and directly in tests.
    static std::string format_diff(const DiffResult& diff);

    // Records that `from` was renamed to `to` (called by the FUSE
    // layer after protecting both paths). Used by
    // build_auto_checkpoint_locked() to avoid reconstructing a
    // checkpoint that contains BOTH the restored original (under
    // `from`) AND the still-damaged file under its new name (`to`):
    // without this, `to` would be seeded from the live tree (since
    // that's where the file now lives) and never get overwritten by
    // the canary overlay, which only knows paths by their ORIGINAL
    // name. A documented prototype-scale limitation: this list is
    // never pruned, so a very long-running daemon under heavy rename
    // traffic will grow it unboundedly; acceptable for the demo/audit
    // scope here, flagged as future work in README.
    //
    // `dest_preexisted` must be true when a file already existed at `to`
    // BEFORE the rename (a rename-over). In that case `to` is a path
    // whose ORIGINAL content is worth restoring (its pre-attack bytes
    // are in the canary because the caller protected `to` first), so
    // the reconstruction must NOT erase it. (Audit finding: the
    // "write temp, rename over original" attack recovered 0/10 before
    // this flag existed, because the original was erased as a mere
    // rename destination.)
    void record_rename(const std::string& from, const std::string& to,
                       bool dest_preexisted = false);

    // Process-scoped repair of ONE path (used when a single offender is
    // detected, instead of a full-tree rollback that would also discard
    // innocent processes' work). The live file is first MOVED into
    // `quarantine_dir` (never deleted), then, if the path existed before
    // the offender touched it, the oldest copy-on-write copy is restored
    // in its place. Returns 1 if restored, 2 if quarantined only (path
    // did not pre-exist), 0 if nothing was done (already identical, or
    // pre-existing but no copy available -- the live file is left alone).
    int repair_path(const std::string& rel, bool existed_before,
                    const std::string& quarantine_dir);

    // Absolute path of the OLDEST surviving copy-on-write copy of `rel`
    // (the pre-attack bytes), or "" if none. Used as ground truth for the
    // differential content analysis.
    std::string oldest_copy(const std::string& rel);

    // undo one repair_path() quarantine (used by `release`): the quarantined file goes back to `rel`; whatever
    // repair put there is moved (never deleted) to `undo_dir`. False if the quarantined copy is gone.
    bool unrepair_path(const std::string& rel, const std::string& quarantine_dir, const std::string& undo_dir);

private:
    int max_scheduled_ = 0;
    std::string oldest_copy_locked(const std::string& rel) const;
    void prune_scheduled_locked();
    std::vector<std::pair<std::string, std::string>> renames_seen_;   // (from,to) for NEW destinations only
    std::string backing_root_;
    std::string canary_root_;
    std::string checkpoint_root_;
    int ring_size_;
    long generation_ = 0;
    mutable std::mutex mu_;
    long min_promote_interval_ms_ = 0;
    std::chrono::steady_clock::time_point last_promote_time_{};

    std::string current_generation_dir() const;
    void rotate_ring_locked();
    // Builds `checkpoint_dir` preferring the oldest available canary
    // copy of each path over the live file; see class comment point 1.
    void build_auto_checkpoint_locked(const std::string& checkpoint_dir);
    static bool copy_file(const std::string& src, const std::string& dst);
    static void copy_tree(const std::string& src, const std::string& dst);
    static void ensure_dir(const std::string& path);
    static void write_meta(const std::string& checkpoint_dir, const CheckpointInfo& info);
    static bool read_meta(const std::string& checkpoint_dir, CheckpointInfo& info);
    // Collects relative paths of all regular files under `root`,
    // skipping the rrfs bookkeeping directory. Used by diff_against()
    // and build_auto_checkpoint_locked().
    static void collect_files(const std::string& root, const std::string& prefix,
                               std::vector<std::string>& out);
    static bool files_identical(const std::string& a, const std::string& b);
};
