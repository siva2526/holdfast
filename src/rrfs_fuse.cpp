// rrfs_fuse.cpp
//
// Ransomware-Resistant File System (prototype) -- a FUSE3 stackable
// filesystem that mounts on top of a "backing_root" directory and:
//
//   1. Scores every write through AnomalyEngine (entropy + overwrite
//      burst + extension churn), per writing process.
//   2. Copy-on-write protects every first-touched-this-generation file
//      through CanaryManager BEFORE the write is allowed to land.
//   3. Auto-promotes a durable, metadata-tagged checkpoint -- now
//      RECONSTRUCTED from pre-attack canary data, see canary_manager.hpp
//      -- when a process's score crosses the configured threshold.
//   4. Optionally freezes (SIGSTOP) the offending process the instant
//      it crosses the threshold -- active containment, not just
//      after-the-fact recovery -- until an operator explicitly
//      resumes it via rrfs_ctl.
//   5. Logs every write/detect/promote/suspend/rollback event as a
//      JSON line to .rrfs_state/events.log for inspection or
//      after-the-fact analysis (overhead/latency measurement etc).
//
// This directly implements the three components proposed on Slide 15
// of the accompanying literature review, as a buildable/testable
// userspace prototype rather than an in-kernel module. All of this is
// DEFENSIVE tooling: it detects and contains file-encrypting activity
// and restores data -- it does not perform any encryption itself.
//
// Changes made in response to an independent audit (AUDIT_REPORT.pdf):
//   - The anomaly engine's burst signal now requires a corroborating
//     per-event signal (high entropy or extension churn) to count a
//     path, instead of counting every write CALL unconditionally; see
//     anomaly_engine.hpp. This is what was freezing ordinary `cp`,
//     `dd`, and `tar -x` at default settings.
//   - Renames now protect the DESTINATION path too, closing the
//     "write-then-rename-over" gap.
//   - Mutating operations under .rrfs_state are rejected with EACCES
//     through the mount (previously any process could delete
//     checkpoints through the FUSE layer despite them being hidden
//     from directory listings).
//   - The control channel now requires the caller's uid to match the
//     daemon's own uid (or root); see kControlPath handling.
//   - promote_checkpoint() is rate-limited (defense against control-
//     channel PROMOTE flooding).
//   - handle_pre_write/handle_pre_rename are now exception-safe.
//   - An optional periodic baseline checkpoint thread closes most of
//     the "no checkpoint predates the attack" gap for workloads where
//     no manual baseline was ever taken.
// None of this makes the daemon tamper-resistant against a privileged
// attacker or a same-uid attacker controlling the mount; see
// README.md's "Known limitations" section for what remains open.
//
// Control interface (pseudo-files inside the mount):
//   cat   <mountpoint>/.rrfs_status
//   echo "PROMOTE"        > <mountpoint>/.rrfs_control
//   echo "ROLLBACK <id>"  > <mountpoint>/.rrfs_control
//   echo "RESUME <pid>"   > <mountpoint>/.rrfs_control
//   echo "DIFF <id>"      > <mountpoint>/.rrfs_control
// (rrfs_ctl wraps these with a nicer CLI -- prefer it. Control writes
// are rejected with EACCES unless the caller's uid matches the
// daemon's uid or is root.)
//
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>   // RENAME_NOREPLACE (glibc >= 2.28)
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "anomaly_engine.hpp"
#include "canary_manager.hpp"
#include "config.hpp"
#include "entropy.hpp"
#include "event_log.hpp"
#include "content_delta.hpp"
#include "ext_tracker.hpp"
#include "holdback.hpp"
#include <unordered_set>

namespace {

std::string g_backing_root;
CanaryManager* g_canary = nullptr;
AnomalyEngine* g_anomaly = nullptr;
EventLog* g_events = nullptr;
bool g_suspend_on_detect = true;
uid_t g_daemon_uid = 0;
std::atomic<long long> g_write_counter{0};

HoldBack* g_hold = nullptr;
bool g_holdback_enabled = true;
long long g_commit_delay_ms = 2000;
size_t g_hold_max_bytes = 64u << 20;
size_t g_hold_max_files = 256;
double g_commit_ceiling_frac = 0.5;   // owner score must stay below frac * threshold to commit
bool g_repair_on_detect = true;
bool g_aggregate_parent = true;
bool g_cluster_block = false;   // a triggered cluster may not rename-over / delete pre-existing files (no SIGSTOP)
bool g_cluster_hold = true;     // cooperation-aware / cumulative hold tier
long long g_cluster_defer_ms = 30000;
bool g_log_writes = true;         // per-write events in events.log (off = faster; detections and alerts are always logged)
bool g_soft_hold = true;          // after a soft alert, the key's held writes are not committed for g_soft_hold_ms
long long g_soft_hold_ms = 30000;
bool g_soft_ckpt = true;          // a soft alert also takes a checkpoint (rebuilt from the original-byte ring)
int g_del_alert = 16;            // E: alert after this many deletes of pre-existing files by one pid (0 = off)
bool g_graded = true;             // soft/hard detection tiers
bool g_shelve = true;             // keep a flagged owner's held writes (hidden) so an operator can release them
bool g_type_conv_benign = true;   // known-format -> different known-format is a conversion, not destruction
double g_entropy_jump_min = 1.0;
bool g_content_delta = true;
int g_amb_policy = 1;                // 0 off, 1 defer (default), 2 freeze
int g_amb_files = 8;
long long g_amb_defer_ms = 30000;
std::string g_state_root;

std::mutex g_control_mutex;
std::string g_last_status = "rrfs ready\n";

std::mutex g_suspended_mutex;
std::set<long> g_suspended_pids;

constexpr const char* kStatusPath = "/.rrfs_status";
constexpr const char* kControlPath = "/.rrfs_control";

std::string full_path(const char* rel) {
    std::string p(rel);
    if (!p.empty() && p.front() == '/') p.erase(0, 1);
    if (p.empty()) return g_backing_root;
    return g_backing_root + "/" + p;
}

std::string rel_of(const char* rel) {
    std::string p(rel);
    if (!p.empty() && p.front() == '/') p.erase(0, 1);
    return p;
}

bool is_rrfs_internal(const std::string& relpath) {
    return relpath.rfind(".rrfs_state", 0) == 0;
}

// Caller is authorized to send control commands if their uid matches
// the daemon's own uid, or is root. This does not stop a same-uid
// attacker (see README limitations: real protection needs the daemon
// running as a separate account), but it does stop an unrelated user
// or process from resuming a contained attacker, deleting checkpoints,
// or rolling back someone else's mount.
bool caller_is_authorized() {
    uid_t caller = fuse_get_context()->uid;
    return caller == g_daemon_uid || caller == 0;
}

// Extension-churn detection lives in ExtensionTracker
// (include/ext_tracker.hpp) so it is independently unit-tested. Only
// on_rename() is used here: on_write() compares a path's extension
// against its own history, which by construction can never change for a
// plain write to the same path.
ExtensionTracker g_ext_tracker;

// ---- process identity & aggregation -----------------------------------------
struct Caller { long pid = -1; long ppid = -1; };

long parent_of(long pid) {
    // /proc/<pid>/stat: "pid (comm) S ppid ..." -- comm may contain spaces/parens.
    FILE* f = fopen(("/proc/" + std::to_string(pid) + "/stat").c_str(), "r");
    if (!f) return -1;
    char buf[1024]; size_t n = fread(buf, 1, sizeof(buf) - 1, f); fclose(f);
    buf[n] = 0;
    const char* rp = strrchr(buf, ')');
    if (!rp) return -1;
    char state; long ppid = -1;
    if (sscanf(rp + 1, " %c %ld", &state, &ppid) != 2) return -1;
    return ppid > 1 ? ppid : -1;
}

std::string exe_of(long pid) {
    char buf[512];
    ssize_t n = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), buf, sizeof(buf) - 1);
    if (n <= 0) return "?";
    return std::string(buf, static_cast<size_t>(n));
}

Caller current_caller() {
    Caller c;
    c.pid = fuse_get_context()->pid;
    c.ppid = g_aggregate_parent ? parent_of(c.pid) : -1;
    return c;
}

// ---- read provenance -----------------------------------------------------
// A process that READ a file (through the mount) and then overwrites that same file with high-entropy bytes is
// transforming what it read (read-encrypt-write), which a plain copy-over of a new version never does (the copy
// does not read the destination). When the original is itself noise the entropy test cannot tell the two apart;
// this signal can. Wipers that overwrite without reading, and tools that read the destination first (rsync
// --checksum, verify-then-overwrite), are the known limits. Off by default (read_provenance = false).
struct ReadRec { long long last_ms; size_t bytes; };
std::mutex g_read_mutex;
std::unordered_map<long, std::unordered_map<std::string, ReadRec>> g_reads;
long long g_read_last_prune = 0;
bool g_provenance = false;
long long g_prov_window_ms = 120000;
double g_prov_min_ham = 0.35;
// A process that writes a recognisable file signature at offset 0 of a file is producing a valid file of a known format
// (image recompressors, document savers), not ciphertext; its later chunks of the same file are exempt from provenance.
std::mutex g_head_mutex;
std::unordered_set<std::string> g_valid_head;
void note_valid_head(long pid, const std::string& rel) {
    std::lock_guard<std::mutex> lk(g_head_mutex);
    if (g_valid_head.size() > 8192) g_valid_head.clear();
    g_valid_head.insert(std::to_string(pid) + '\0' + rel);
}
bool has_valid_head(long pid, const std::string& rel) {
    std::lock_guard<std::mutex> lk(g_head_mutex);
    return g_valid_head.count(std::to_string(pid) + '\0' + rel) > 0;
}
void note_read(const std::string& rel, size_t n) {
    long pid = fuse_get_context()->pid;
    long pp = parent_of(pid);
    long long now = HoldBack::now_ms();
    std::lock_guard<std::mutex> lk(g_read_mutex);
    for (long k : {pid, pp}) {
        if (k <= 1) continue;
        auto& m = g_reads[k];
        auto& r = m[rel]; r.last_ms = now; r.bytes += n;
        if (m.size() > 4096) m.clear();
    }
    if (now - g_read_last_prune > 30000) {
        g_read_last_prune = now;
        for (auto it = g_reads.begin(); it != g_reads.end();) {
            for (auto jt = it->second.begin(); jt != it->second.end();)
                jt = (now - jt->second.last_ms > g_prov_window_ms) ? it->second.erase(jt) : std::next(jt);
            it = it->second.empty() ? g_reads.erase(it) : std::next(it);
        }
    }
}
bool read_before(const Caller& c, const std::string& rel) {
    long long now = HoldBack::now_ms();
    std::lock_guard<std::mutex> lk(g_read_mutex);
    for (long k : {c.pid, c.ppid}) {
        auto it = g_reads.find(k);
        if (it == g_reads.end()) continue;
        auto jt = it->second.find(rel);
        if (jt != it->second.end() && now - jt->second.last_ms <= g_prov_window_ms) return true;
    }
    return false;
}

// Keys (pid or parent bucket) that have been detected: every further
// mutation by them is refused until an operator resumes them. This closes
// the window in which the in-flight operation that tripped the detector
// (or a sibling process in the same bucket) would otherwise still land.
std::mutex g_blocked_mutex;
std::set<long> g_blocked;
bool is_blocked(const Caller& c) {
    std::lock_guard<std::mutex> lk(g_blocked_mutex);
    return g_blocked.count(c.pid) || (c.ppid > 0 && g_blocked.count(c.ppid));
}

// ---- undo journal (for process-scoped repair of namespace operations) ------
struct JEntry { long long ts_ms; long pid, ppid; std::string rel; bool existed; };
std::mutex g_journal_mutex;
std::vector<JEntry> g_journal;
std::unordered_set<std::string> g_journal_seen;
long long g_journal_last_prune = 0;

void journal_add(const Caller& c, const std::string& rel, bool existed) {
    std::lock_guard<std::mutex> lk(g_journal_mutex);
    std::string key = std::to_string(c.pid) + '\0' + rel;
    if (!g_journal_seen.insert(key).second) return;     // first touch per (pid, path) decides "existed"
    long long now = HoldBack::now_ms();
    g_journal.push_back({now, c.pid, c.ppid, rel, existed});
    if (now - g_journal_last_prune > 60000 || g_journal.size() > 200000) {   // keep ~15 min
        g_journal_last_prune = now;
        std::vector<JEntry> keep; g_journal_seen.clear();
        for (auto& e : g_journal)
            if (now - e.ts_ms < 900000) { keep.push_back(e); g_journal_seen.insert(std::to_string(e.pid) + '\0' + e.rel); }
        g_journal.swap(keep);
    }
}

// remember what a repair moved so an operator `release` can put it back.
struct RepairRec { std::vector<long> keys; std::string rel, qdir; };
std::mutex g_repair_mutex;
std::vector<RepairRec> g_repairs;

// Undo everything the offending keys did: pending (held) copies are
// discarded, namespace/content damage that already landed is reverted from
// the copy-on-write ring, attacker-created files are QUARANTINED (moved,
// never deleted). Only paths the offender touched are affected -- other
// processes' unrelated work survives, unlike a full-tree rollback.
void repair_for_keys(const std::vector<long>& keys, double score) {
    size_t reverted = 0, restored = 0, quarantined = 0;
    for (long k : keys) reverted += g_shelve ? g_hold->shelve_owner(k) : g_hold->revert_owner(k).size();
    if (g_repair_on_detect) {
        std::vector<JEntry> mine;
        {
            std::lock_guard<std::mutex> lk(g_journal_mutex);
            std::vector<JEntry> keep;
            for (auto& e : g_journal) {
                bool match = false;
                for (long k : keys) if (e.pid == k || e.ppid == k) match = true;
                (match ? mine : keep).push_back(e);
            }
            g_journal.swap(keep);
            g_journal_seen.clear();
            for (auto& e : g_journal) g_journal_seen.insert(std::to_string(e.pid) + '\0' + e.rel);
        }
        std::string qdir = g_state_root + "/quarantine/" + std::to_string(HoldBack::now_ms());
        std::unordered_set<std::string> done;
        for (auto& e : mine) {                      // oldest first: earliest "existed" wins
            if (!done.insert(e.rel).second) continue;
            int r = g_canary->repair_path(e.rel, e.existed, qdir);
            if (r == 1) ++restored; else if (r == 2) ++quarantined;
            if (r == 1 || r == 2) {
                struct stat qs{};
                if (lstat((qdir + "/" + e.rel).c_str(), &qs) == 0) {
                    std::lock_guard<std::mutex> rl(g_repair_mutex);
                    g_repairs.push_back({keys, e.rel, qdir});
                }
            }
        }
    }
    g_events->log("repair", keys.empty() ? -1 : keys[0], "", -1, score, "",
                   (std::string(g_shelve ? "held writes shelved=" : "held writes discarded=")) + std::to_string(reverted) +
                   " files restored=" + std::to_string(restored) +
                   " attacker files quarantined=" + std::to_string(quarantined));
}

// Detection response, shared by every scored event. `keys` are the pid /
// parent-bucket keys whose score crossed the threshold.
void respond_to_detection(const Caller& c, const std::vector<long>& keys, const std::string& relpath,
                          double entropy, double score) {
    g_events->log("detect", c.pid, relpath, entropy, score, "",
                   "composite score crossed promote_threshold");
    {
        std::lock_guard<std::mutex> lk(g_blocked_mutex);
        for (long k : keys) g_blocked.insert(k);
    }
    if (g_suspend_on_detect) {
        std::vector<long> targets = keys;
        if (std::find(targets.begin(), targets.end(), c.pid) == targets.end()) targets.push_back(c.pid);
        for (long t : targets) {
            if (t > 1 && kill(static_cast<pid_t>(t), SIGSTOP) == 0) {
                std::lock_guard<std::mutex> lk(g_suspended_mutex);
                g_suspended_pids.insert(t);
                g_events->log("suspend", t, "", -1, score, "", "SIGSTOP sent");
            }
        }
    }
    repair_for_keys(keys, score);

    std::string id = g_canary->promote_checkpoint("auto", c.pid, score);
    for (long k : keys) g_anomaly->reset(k);

    std::lock_guard<std::mutex> lk(g_control_mutex);
    if (id.empty()) {
        g_events->log("promote", c.pid, "", -1, score, "", "auto-promotion REJECTED by rate limiter");
        g_last_status = "DETECTED pid " + std::to_string(c.pid) + " (score=" + std::to_string(score) +
                         ") but auto-checkpoint was rate-limited -- see the most recent checkpoint instead\n";
    } else {
        g_events->log("promote", c.pid, "", -1, score, id, "auto-promoted on detection");
        g_last_status = "AUTO-PROMOTED checkpoint " + id + " (pid " + std::to_string(c.pid) +
                         " crossed threshold, score=" + std::to_string(score) + ")" +
                         (g_suspend_on_detect ? " -- suspended; held writes discarded and its files repaired. "
                                                "Resume with:\n  rrfs_ctl <mount> resume " + std::to_string(c.pid) + "   (or, if this is a false positive: release " + std::to_string(c.pid) + " to commit its held writes)\n"
                                              : "\n");
    }
}

// Score one event for the writer AND its parent bucket (process-tree
// aggregation: a shell loop that spawns one process per file is one
// attacker). Returns true if a detection fired and the operation must be
// refused.
bool score_and_respond(const Caller& c, const std::string& relpath, double entropy,
                       bool ext_changed, bool type_changed = false) {
    double s_pid = g_anomaly->record_write(c.pid, relpath, entropy, ext_changed, type_changed);
    double s_bucket = c.ppid > 0 ? g_anomaly->record_write(c.ppid, relpath, entropy, ext_changed, type_changed) : 0.0;
    double score = std::max(s_pid, s_bucket);
    if (g_log_writes || score > 0) g_events->log("write", c.pid, relpath, entropy, score);
    if (score < g_anomaly->promote_threshold) return false;
    std::vector<long> keys;
    bool soft_only = false;
    auto hard_ok = [&](long k) { return !g_graded || g_anomaly->content_files(static_cast<pid_t>(k)) >= g_anomaly->hard_min_content_files; };
    if (s_pid >= g_anomaly->promote_threshold) { if (hard_ok(c.pid)) keys.push_back(c.pid); else soft_only = true; }
    if (s_bucket >= g_anomaly->promote_threshold) { if (hard_ok(c.ppid)) keys.push_back(c.ppid); else soft_only = true; }
    if (keys.empty()) {
        // SOFT detection: namespace/extension activity alone. Log + alert, never stop or block anyone.
        if (soft_only && g_anomaly->soft_alert_due(static_cast<pid_t>(c.ppid > 0 ? c.ppid : c.pid), std::chrono::seconds(60))) {
            g_events->log("detect_soft", c.pid, relpath, entropy, score, "",
                           "threshold crossed with no content evidence (rename/extension activity only); nobody is stopped");
            if (g_soft_ckpt) {
                std::string id = g_canary->promote_checkpoint("soft", c.pid, score);
                if (!id.empty()) g_events->log("promote", c.pid, "", -1, score, id, "checkpoint taken on soft alert");
            }
        }
        return false;
    }
    respond_to_detection(c, keys, relpath, entropy, score);
    return true;
}

// Is this write destructive, i.e. does it clobber bytes that already exist
// (or follow a truncation of existing data by the same process, or land on
// a file that is already held back)?
// `bytes_only` = judge purely by whether pre-existing bytes are clobbered (used for SCORING); without it
// a write to an already-held file also counts (used to route the write into the pending copy).
// A file the caller created itself (zip's temp archive, a compiler's .o) holds no one else's data:
// patching it is never destructive.
bool write_is_destructive(const Caller& c, const std::string& relpath, off_t offset, bool bytes_only = false) {
    if (g_anomaly->is_created(c.pid, relpath)) return false;
    if (!bytes_only && g_hold->is_held(relpath)) return true;
    struct stat st;
    if (lstat(full_path(("/" + relpath).c_str()).c_str(), &st) == 0 && offset < st.st_size) return true;
    return g_anomaly->is_destroyed(c.pid, relpath);
}

// Content-destroying evidence from ANY path (in-place write, rename-over, delete-after-fresh-noise) feeds the
// cooperation/cumulative hold tier. On the first trigger it also takes a checkpoint so the operator can roll back.
void note_content_evidence(const Caller& c, const std::string& relpath) {
    if (!g_cluster_hold) return;
    g_anomaly->note_cluster(exe_of(c.pid), c.pid, relpath);
    g_anomaly->note_cluster("*", c.pid, relpath);
    std::string cl = g_anomaly->cluster_hold(c.pid, g_cluster_defer_ms);
    if (cl.empty()) return;
    static std::mutex m; static long long last = 0;
    std::lock_guard<std::mutex> lkc(m);
    long long nowm = HoldBack::now_ms();
    if (nowm - last <= 60000) return;
    last = nowm;
    std::string id = g_canary->promote_checkpoint("cluster", c.pid, -1);
    g_events->log("cluster", c.pid, relpath, -1, -1, id,
                   "cooperating/cumulative content-evidence writes (" + cl + "); commits withheld, nobody stopped; checkpoint " + (id.empty() ? "rate-limited" : id));
    std::lock_guard<std::mutex> lk(g_control_mutex);
    g_last_status = "CLUSTER ALERT (" + cl + "): many processes/files show content-destroying writes; their held commits are withheld" +
                    (id.empty() ? "" : "; checkpoint " + id + " taken (rrfs_ctl <mount> rollback " + id + ")") + ". Review, then:\n"
                    "  rrfs_ctl <mount> discard cluster   (drop the held writes of all cluster members)\n";
}

// while a cluster hold covers this pid, replace-style mutations of pre-existing files are refused (EACCES). Nobody is stopped:
// the hold already withholds commits of in-place writes; this closes the rename-over / delete path that hold-back cannot cover.
bool cluster_blocks_replace(const Caller& c, const std::string& relpath) {
    if (!g_cluster_hold || !g_cluster_block) return false;
    if (g_anomaly->is_created(c.pid, relpath)) return false;
    if (g_anomaly->cluster_hold(c.pid, g_cluster_defer_ms).empty()) return false;
    g_events->log("cluster_block", c.pid, relpath, -1, -1, "", "replace/delete of a pre-existing file refused while the cluster hold is active");
    return true;
}

enum class Op { Write, Truncate, Delete };

struct PreResult { int err = 0; bool destructive = false; };

// Reads up to n bytes of the ORIGINAL content of `relpath` at `offset`:
// the oldest copy-on-write copy if one exists, else the backing file
// (which IS the original for held files).
size_t read_original(const std::string& relpath, off_t offset, size_t n, std::vector<uint8_t>& out) {
    std::string src = g_canary->oldest_copy(relpath);
    if (src.empty()) src = full_path(("/" + relpath).c_str());
    int fd = open(src.c_str(), O_RDONLY);
    if (fd < 0) return 0;
    out.assign(n, 0);
    ssize_t r = pread(fd, out.data(), n, offset);
    close(fd);
    if (r < 0) r = 0;
    out.resize(static_cast<size_t>(r));
    return out.size();
}

// `offset` is only meaningful for Op::Write. Op::Truncate: truncate / open
// with O_TRUNC. Op::Delete: unlink.
PreResult handle_pre_write(const char* rel, const char* buf, size_t size,
                           Op op = Op::Write, off_t offset = 0) {
    PreResult res;
    std::string relpath = rel_of(rel);
    if (is_rrfs_internal(relpath)) return res;
    Caller c = current_caller();
    if (is_blocked(c)) { res.err = -EACCES; return res; }

    try {
        bool have = false; struct stat st{};
        have = lstat(full_path(("/" + relpath).c_str()).c_str(), &st) == 0;
        bool destructive;
        if (op == Op::Write) destructive = write_is_destructive(c, relpath, offset);
        else if (op == Op::Truncate) destructive = have && st.st_size > 0;
        else destructive = have && !(op == Op::Delete && g_anomaly->is_created(c.pid, relpath));   // removing your own temp file destroys nothing
        res.destructive = destructive;
        if (op == Op::Delete && destructive && cluster_blocks_replace(c, relpath)) { res.err = -EACCES; return res; }
        // For scoring, a write into an already-held file that lands beyond the original bytes (an
        // append) destroys nothing; only genuinely clobbered bytes count.
        const bool score_destr = (op == Op::Write) ? write_is_destructive(c, relpath, offset, true) : destructive;

        // Differential analysis uses the original bytes, so take it BEFORE
        // the copy-on-write protect / any modification.
        DeltaVerdict verdict;
        double h_new = 0.0;
        double ham_frac = -1.0;      // fraction of differing bits between old and new over the compared range (random vs random: ~0.5)
        if (op == Op::Write) {
            h_new = bias_corrected_entropy(
                shannon_entropy(reinterpret_cast<const uint8_t*>(buf), size), size);
            if (score_destr && g_content_delta) {
                std::vector<uint8_t> old;
                size_t n = std::min<size_t>(size, 65536);
                if (read_original(relpath, offset, n, old) > 0) {
                    size_t m = std::min(old.size(), size);
                    if (m >= 64) {
                        size_t bits = 0;
                        for (size_t i = 0; i < m; ++i) bits += __builtin_popcount(static_cast<unsigned>(old[i] ^ static_cast<uint8_t>(buf[i])));
                        ham_frac = static_cast<double>(bits) / (8.0 * static_cast<double>(m));
                    }
                }
                if (!old.empty())
                    verdict = compare_old_new(old.data(), old.size(),
                                              reinterpret_cast<const uint8_t*>(buf), old.size(),
                                              offset, h_new, g_entropy_jump_min, g_type_conv_benign);
            }
        }

        g_canary->protect_before_write(relpath);
        g_write_counter.fetch_add(1, std::memory_order_relaxed);
        if (op == Op::Truncate && destructive) g_anomaly->mark_destroyed(c.pid, relpath);

        if (op == Op::Delete) {
            if (destructive) journal_add(c, relpath, true);
            if (destructive && g_del_alert > 0) {
                // E (alert-only): a process deleting many pre-existing files it did not create is logged, never frozen --
                // plain deletes carry no content evidence, and rm/rsync --delete/make clean are ordinary.
                int nd = g_anomaly->note_cluster("del:" + std::to_string(c.pid), c.pid, relpath);
                if (nd == g_del_alert)
                    g_events->log("detect_soft", c.pid, relpath, -1, -1, "",
                                   "bulk delete of pre-existing files (" + std::to_string(nd) + " in window); no action taken. Latest checkpoint can restore them.");
            }
            if (destructive && g_anomaly->has_fresh_high_entropy(c.pid)) {
                note_content_evidence(c, relpath);
                if (score_and_respond(c, relpath, 8.0, false)) res.err = -EACCES;
            }
            return res;
        }
        if (score_destr) {
            journal_add(c, relpath, true);
            // With original bytes available: only content that became noise counts.
            double scored_entropy = h_new;
            bool type_changed = false;
            if (g_provenance && op == Op::Write && offset == 0 && detect_magic(reinterpret_cast<const uint8_t*>(buf), size) != FileType::None)
                note_valid_head(c.pid, relpath);
            if (verdict.old_known) {
                bool prov = g_provenance && op == Op::Write && !verdict.content_suspicious() &&
                            verdict.h_old >= g_anomaly->entropy_high_water && h_new >= g_anomaly->entropy_high_water &&
                            ham_frac >= g_prov_min_ham && !has_valid_head(c.pid, relpath) && read_before(c, relpath);   // a small edit of the old bytes is not a transform
                if (prov && g_anomaly->note_cluster("prov:" + std::to_string(c.pid), c.pid, relpath) == 1)
                    g_events->log("provenance", c.pid, relpath, h_new, -1, "",
                                   "process read this file and overwrote it with high-entropy data (read-transform-write); scored as destroyed content");
                scored_entropy = (verdict.content_suspicious() || prov) ? h_new : 0.0;
                type_changed = verdict.type_destroyed || verdict.text_destroyed || prov;
            }
            if (score_and_respond(c, relpath, scored_entropy, false, type_changed)) { res.err = -EACCES; return res; }
            if (type_changed || scored_entropy >= g_anomaly->entropy_high_water) note_content_evidence(c, relpath);
            // Blind-spot handling: noise replacing noise with no content evidence.
            if (g_amb_policy != 0 && op == Op::Write && verdict.old_known && !verdict.content_suspicious() &&
                verdict.h_old >= g_anomaly->entropy_high_water && h_new >= g_anomaly->entropy_high_water) {
                int n = g_anomaly->note_ambiguous(c.pid, relpath);
                if (n == g_amb_files) {
                    if (g_soft_ckpt) {   // deferral is only 30 s; leave a recoverable checkpoint behind
                        std::string cid = g_canary->promote_checkpoint("soft", c.pid, -1);
                        if (!cid.empty()) g_events->log("promote", c.pid, "", -1, -1, cid, "checkpoint taken on ambiguous (noise-over-noise) alert");
                    }
                    g_events->log("ambiguous", c.pid, relpath, h_new, -1, "",
                                   std::string("bulk high-entropy overwrite with no content evidence; policy=") +
                                   (g_amb_policy == 2 ? "freeze" : "defer"));
                    std::lock_guard<std::mutex> lk(g_control_mutex);
                    g_last_status = "AMBIGUOUS: pid " + std::to_string(c.pid) + " overwrote " + std::to_string(n) +
                                    " high-entropy files with high-entropy data; their commit is deferred. Review, then:\n"
                                    "  rrfs_ctl <mount> discard " + std::to_string(c.pid) + "   (drop its held writes)\n";
                }
                if (g_amb_policy == 2 && n >= g_amb_files) {
                    respond_to_detection(c, {c.pid}, relpath, h_new, g_anomaly->promote_threshold);
                    res.err = -EACCES; return res;
                }
            }
        } else if (op == Op::Write) {
            // Non-destructive (new / extended file). A recognised signature at
            // offset 0 marks a benign copy/download/archive; otherwise a
            // high-entropy fresh file is remembered (not scored) in case this
            // process later replaces or deletes an existing file with it.
            if (offset == 0 && detect_magic(reinterpret_cast<const uint8_t*>(buf), size) != FileType::None) {
                g_anomaly->note_typed_fresh(c.pid, relpath);
            } else if (h_new >= g_anomaly->entropy_high_water) {
                g_anomaly->note_fresh_high_entropy(c.pid, relpath);
                journal_add(c, relpath, false);                    // quarantined if this process is flagged
            }
        }
    } catch (const std::exception& e) {
        g_events->log("write", -1, relpath, -1, -1, "",
                       std::string("INTERNAL ERROR (swallowed): ") + e.what());
    } catch (...) {
        g_events->log("write", -1, relpath, -1, -1, "", "INTERNAL ERROR (swallowed, unknown)");
    }
    return res;
}

// Returns 0, or a negative errno if the rename must be refused.
int handle_pre_rename(const char* from_rel, const char* to_rel) {
    std::string from = rel_of(from_rel);
    std::string to = rel_of(to_rel);
    if (is_rrfs_internal(from) || is_rrfs_internal(to)) return 0;
    Caller c = current_caller();
    if (is_blocked(c)) return -EACCES;

    try {
        struct stat dst_st, src_st;
        const bool dest_existed = lstat(full_path(to_rel).c_str(), &dst_st) == 0;
        const bool src_existed = lstat(full_path(from_rel).c_str(), &src_st) == 0;
        if (dest_existed && cluster_blocks_replace(c, to)) return -EACCES;
        // Preserve the pre-rename content under its ORIGINAL name AND the
        // destination's current content (a rename replaces it).
        g_canary->protect_before_write(from);
        g_canary->protect_before_write(to);
        g_canary->record_rename(from, to, dest_existed);
        g_write_counter.fetch_add(1, std::memory_order_relaxed);
        journal_add(c, from, src_existed);
        journal_add(c, to, dest_existed);

        bool ext_changed = g_ext_tracker.on_rename(from, to);
        // temp-file-then-rename-to-final-name is the standard save pattern
        // (sed -i, editors, browsers); it is not extension churn.
        if (g_anomaly->take_created(c.pid, from) && ext_changed) {
            size_t dot = from.find_last_of('.'), slash = from.find_last_of('/');
            std::string fext = (dot == std::string::npos || (slash != std::string::npos && dot < slash)) ? "" : from.substr(dot);
            if (fext.empty() || fext == ".tmp" || fext == ".part" || fext == ".temp" || fext == ".swp" || fext == ".download" ||
                fext == ".lock")
                ext_changed = false;
            // lockfile / temp-suffix pattern: "<final>.<anything>" created by this very process and renamed to "<final>"
            else if (from.size() > to.size() + 1 && from.compare(0, to.size(), to) == 0 && from[to.size()] == '.')
                ext_changed = false;
        }
        // A file this PID filled with high-entropy bytes REPLACING an
        // existing file is "encrypt to temp, rename over original".
        bool replaced = g_anomaly->take_fresh_high_entropy(c.pid, from) && dest_existed;
        if (replaced) note_content_evidence(c, to);
        if (score_and_respond(c, to, replaced ? 8.0 : 0.0, ext_changed)) return -EACCES;
    } catch (const std::exception& e) {
        g_events->log("write", -1, to, -1, -1, "", std::string("INTERNAL ERROR (swallowed): ") + e.what());
    } catch (...) {
        g_events->log("write", -1, to, -1, -1, "", "INTERNAL ERROR (swallowed, unknown)");
    }
    return 0;
}

std::string build_status_report() {
    std::lock_guard<std::mutex> lk(g_control_mutex);
    std::ostringstream ss;
    ss << g_last_status;

    ss << "\nsuspended pids:\n";
    {
        std::lock_guard<std::mutex> lk2(g_suspended_mutex);
        if (g_suspended_pids.empty()) ss << "  (none)\n";
        for (long pid : g_suspended_pids) ss << "  " << pid << "\n";
    }

    ss << "\nheld-back (uncommitted) writes: " << (g_hold ? g_hold->count() : 0) << "\n";
    ss << "\ncheckpoints (oldest first):\n";
    for (auto& c : g_canary->list_checkpoints()) {
        ss << "  " << c.id << "  reason=" << c.reason;
        if (c.trigger_pid >= 0) ss << " pid=" << c.trigger_pid;
        if (c.trigger_score >= 0) ss << " score=" << c.trigger_score;
        ss << "\n";
    }

    ss << "\nrecent events:\n";
    for (auto& line : g_events->tail(15)) ss << "  " << line << "\n";

    return ss.str();
}

// ---- standard passthrough operations -------------------------------------

int rrfs_getattr(const char* path, struct stat* stbuf, struct fuse_file_info*) {
    if (std::string(path) == kStatusPath || std::string(path) == kControlPath) {
        memset(stbuf, 0, sizeof(struct stat));
        stbuf->st_mode = S_IFREG | 0666;
        stbuf->st_nlink = 1;
        stbuf->st_size = 65536;
        return 0;
    }
    HoldBack::Access acc(*g_hold, rel_of(path));
    int res = lstat(acc.path().c_str(), stbuf);
    return res == -1 ? -errno : 0;
}

int rrfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t,
                  struct fuse_file_info*, enum fuse_readdir_flags) {
    std::string fp = full_path(path);
    DIR* dp = opendir(fp.c_str());
    if (!dp) return -errno;

    filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));

    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        std::string name = de->d_name;
        if (name == "." || name == "..") continue;
        if (name == ".rrfs_state") continue; // hide internal bookkeeping
        filler(buf, de->d_name, nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    }
    closedir(dp);

    if (std::string(path) == "/") {
        filler(buf, ".rrfs_status", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
        filler(buf, ".rrfs_control", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    }
    return 0;
}

int rrfs_open(const char* path, struct fuse_file_info* fi) {
    if (std::string(path) == kStatusPath || std::string(path) == kControlPath) {
        return 0;
    }
    if (is_rrfs_internal(rel_of(path)) && (fi->flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND))) {
        return -EACCES;
    }
    // With FUSE_ATOMIC_O_TRUNC (libfuse3 default) a truncating open()
    // arrives HERE with O_TRUNC set, and the backing open() below would
    // destroy the data before any canary copy exists (python open(...,"wb"),
    // shell `>`). Protect first, exactly as rrfs_truncate does.
    int flags = fi->flags;
    if (!is_rrfs_internal(rel_of(path)) && (flags & O_TRUNC)) {
        PreResult pr = handle_pre_write(path, "", 0, Op::Truncate);
        if (pr.err) return pr.err;
        std::string rel = rel_of(path);
        if (g_holdback_enabled && pr.destructive) {
            Caller c = current_caller();
            if (g_hold->hold(rel, c.pid, c.ppid, g_hold_max_bytes)) {
                int tr;
                { HoldBack::Access acc(*g_hold, rel); tr = truncate(acc.path().c_str(), 0); }
                if (tr != 0) return -errno;
                g_hold->touch(rel, c.pid, c.ppid);   // (after the shared lock is released)
                flags &= ~O_TRUNC;     // the backing original must stay untouched
            }
        }
    }
    HoldBack::Access acc(*g_hold, rel_of(path));
    int fd = open(acc.path().c_str(), flags);
    if (fd == -1) return -errno;
    close(fd);
    return 0;
}

int rrfs_read(const char* path, char* buf, size_t size, off_t offset,
              struct fuse_file_info*) {
    if (std::string(path) == kStatusPath) {
        std::string s = build_status_report();
        if (static_cast<size_t>(offset) >= s.size()) return 0;
        size_t n = std::min(size, s.size() - static_cast<size_t>(offset));
        memcpy(buf, s.data() + offset, n);
        return static_cast<int>(n);
    }
    if (std::string(path) == kControlPath) {
        return 0;
    }

    HoldBack::Access acc(*g_hold, rel_of(path));
    int fd = open(acc.path().c_str(), O_RDONLY);
    if (fd == -1) return -errno;
    ssize_t res = pread(fd, buf, size, offset);
    close(fd);
    if (g_provenance && res > 0) note_read(rel_of(path), static_cast<size_t>(res));
    return res == -1 ? -errno : static_cast<int>(res);
}

int rrfs_write(const char* path, const char* buf, size_t size, off_t offset,
               struct fuse_file_info*) {
    if (std::string(path) == kControlPath) {
        if (!caller_is_authorized()) return -EACCES;

        std::string cmd(buf, size);
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) cmd.pop_back();
        std::istringstream iss(cmd);
        std::string verb;
        iss >> verb;
        std::lock_guard<std::mutex> lk(g_control_mutex);
        if (verb == "PROMOTE") {
            std::string mode; iss >> mode;
            std::string id = g_canary->promote_checkpoint(mode == "recover" ? "cluster" : "manual", -1, -1);
            if (id.empty()) {
                g_events->log("promote", -1, "", -1, -1, "", "manual promotion REJECTED by rate limiter");
                g_last_status = "PROMOTE rejected: too soon after the previous checkpoint "
                                 "(see promote_min_interval_ms in rrfs.conf)\n";
            } else {
                g_events->log("promote", -1, "", -1, -1, id, "manual promotion");
                g_last_status = "manually promoted checkpoint " + id + "\n";
            }
        } else if (verb == "ROLLBACK") {
            std::string id;
            iss >> id;
            bool ok = g_canary->rollback(id);
            g_events->log("rollback", -1, "", -1, -1, id, ok ? "ok" : "failed");
            g_last_status = ok ? ("rolled back to " + id + "\n")
                               : ("ROLLBACK FAILED: unknown checkpoint " + id + "\n");
        } else if (verb == "DISCARD") {
            std::string tok;
            iss >> tok;
            long pid = 0;
            size_t n = 0;
            if (tok == "cluster") {
                std::set<long> owners;
                for (auto& h : g_hold->list()) {
                    if (!g_anomaly->cluster_hold(static_cast<pid_t>(h.owner_pid), g_cluster_defer_ms).empty() ||
                        (h.owner_ppid > 0 && !g_anomaly->cluster_hold(static_cast<pid_t>(h.owner_ppid), g_cluster_defer_ms).empty()))
                        owners.insert(h.owner_pid);
                }
                for (long o : owners) n += g_hold->revert_owner(o).size();
            } else {
                pid = std::atol(tok.c_str());
                n = g_hold->revert_owner(pid).size();
            }
            g_events->log("discard", pid, "", -1, -1, "", "operator discarded " + std::to_string(n) + " held writes");
            g_last_status = "discarded " + std::to_string(n) + " held writes of pid " + std::to_string(pid) + "\n";
        } else if (verb == "RELEASE") {
            // False-positive override: commit the owner's shelved writes, un-block and resume it.
            long pid = 0;
            iss >> pid;
            size_t n = g_hold->release_owner(pid).size();
            size_t undone = 0;
            {   // put back what the detection-time repair moved (quarantined files return; the restored version is kept in undo/)
                long pp0 = parent_of(pid);
                std::string undo = g_state_root + "/undo/" + std::to_string(HoldBack::now_ms());
                std::lock_guard<std::mutex> rl(g_repair_mutex);
                for (auto it = g_repairs.begin(); it != g_repairs.end();) {
                    bool mine = false;
                    for (long k : it->keys) if (k == pid || (pp0 > 0 && k == pp0)) mine = true;
                    if (mine) { if (g_canary->unrepair_path(it->rel, it->qdir, undo)) ++undone; it = g_repairs.erase(it); }
                    else ++it;
                }
            }
            { std::lock_guard<std::mutex> lk2(g_suspended_mutex); g_suspended_pids.erase(pid); }
            { std::lock_guard<std::mutex> lk3(g_blocked_mutex); g_blocked.erase(pid); long pp = parent_of(pid); if (pp > 0) g_blocked.erase(pp); }
            bool ok = (kill(static_cast<pid_t>(pid), SIGCONT) == 0);
            {   // the detector also stopped the offender's parent bucket; a release must undo that too
                long pp = parent_of(pid);
                std::lock_guard<std::mutex> lk4(g_suspended_mutex);
                if (pp > 1 && g_suspended_pids.erase(pp)) kill(static_cast<pid_t>(pp), SIGCONT);
            }
            g_events->log("release", pid, "", -1, -1, "", "operator released " + std::to_string(n) + " shelved writes, undid " + std::to_string(undone) + " repairs; resume " + (ok ? "ok" : "failed"));
            g_last_status = "released pid " + std::to_string(pid) + ": " + std::to_string(n) + " shelved writes committed, " + std::to_string(undone) + " repaired paths put back" + (ok ? "" : " (process not resumable)") + "\n";
        } else if (verb == "RESUME") {
            long pid = 0;
            iss >> pid;
            {
                std::lock_guard<std::mutex> lk2(g_suspended_mutex);
                g_suspended_pids.erase(pid);
            }
            {
                std::lock_guard<std::mutex> lk3(g_blocked_mutex);
                g_blocked.erase(pid);
                long pp = parent_of(pid);
                if (pp > 0) g_blocked.erase(pp);
            }
            bool ok = (kill(static_cast<pid_t>(pid), SIGCONT) == 0);
            {
                long pp = parent_of(pid);
                std::lock_guard<std::mutex> lk4(g_suspended_mutex);
                if (pp > 1 && g_suspended_pids.erase(pp)) kill(static_cast<pid_t>(pp), SIGCONT);
            }
            g_events->log("resume", pid, "", -1, -1, "", ok ? "ok" : "failed");
            g_last_status = ok ? ("resumed pid " + std::to_string(pid) + "\n")
                               : ("RESUME FAILED for pid " + std::to_string(pid) + "\n");
        } else if (verb == "DIFF") {
            std::string id;
            iss >> id;
            bool known = false;
            for (auto& c : g_canary->list_checkpoints()) {
                if (c.id == id) { known = true; break; }
            }
            if (!known) {
                g_last_status = "DIFF FAILED: unknown checkpoint " + id + "\n";
            } else {
                auto diff = g_canary->diff_against(id);
                g_events->log("diff", -1, "", -1, -1, id,
                               std::to_string(diff.modified.size()) + " modified, " +
                                   std::to_string(diff.added.size()) + " added, " +
                                   std::to_string(diff.removed.size()) + " removed");
                g_last_status = "diff vs " + id + ":\n" + CanaryManager::format_diff(diff);
            }
        } else {
            g_last_status = "unknown command: " + cmd + "\n";
        }
        return static_cast<int>(size);
    }
    if (std::string(path) == kStatusPath) {
        return static_cast<int>(size);
    }

    std::string relpath = rel_of(path);
    if (is_rrfs_internal(relpath)) return -EACCES; // reject mutation of rrfs' own bookkeeping

    PreResult pr = handle_pre_write(path, buf, size, Op::Write, offset);
    if (pr.err) return pr.err;                     // blocked / detection tripped on this very write

    Caller c = current_caller();
    if (g_holdback_enabled && pr.destructive) g_hold->hold(relpath, c.pid, c.ppid, g_hold_max_bytes);
    ssize_t res; int err = 0; bool was_held;
    {
        HoldBack::Access acc(*g_hold, relpath);    // pending copy if held, else the backing file
        was_held = acc.held();
        int fd = open(acc.path().c_str(), O_WRONLY);
        if (fd == -1) { err = errno; res = -1; }
        else { res = pwrite(fd, buf, size, offset); if (res == -1) err = errno; close(fd); }
    }
    if (was_held) g_hold->touch(relpath, c.pid, c.ppid);   // touch() needs the exclusive lock
    return res == -1 ? -err : static_cast<int>(res);
}

int rrfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    if (is_rrfs_internal(rel_of(path))) return -EACCES;
    Caller cc = current_caller();
    if (is_blocked(cc)) return -EACCES;
    int fd = open(full_path(path).c_str(), fi->flags, mode);
    if (fd == -1) return -errno;
    close(fd);
    g_anomaly->note_created(cc.pid, rel_of(path));
    return 0;
}

int rrfs_truncate(const char* path, off_t size, struct fuse_file_info*) {
    if (is_rrfs_internal(rel_of(path))) return -EACCES;
    PreResult pr = handle_pre_write(path, "", 0, Op::Truncate);
    if (pr.err) return pr.err;
    std::string rel = rel_of(path);
    Caller c = current_caller();
    if (g_holdback_enabled && pr.destructive) g_hold->hold(rel, c.pid, c.ppid, g_hold_max_bytes);
    int res, err = 0; bool was_held;
    {
        HoldBack::Access acc(*g_hold, rel);
        was_held = acc.held();
        res = truncate(acc.path().c_str(), size);
        if (res == -1) err = errno;
    }
    if (res == 0 && was_held) g_hold->touch(rel, c.pid, c.ppid);
    return res == -1 ? -err : 0;
}

int rrfs_unlink(const char* path) {
    if (is_rrfs_internal(rel_of(path))) return -EACCES;
    PreResult pr = handle_pre_write(path, "", 0, Op::Delete);
    if (pr.err) return pr.err;
    int res = unlink(full_path(path).c_str());
    if (res == 0) g_hold->drop(rel_of(path));      // a deleted file's pending copy is moot
    return res == -1 ? -errno : 0;
}

int rrfs_rename(const char* from, const char* to, unsigned int flags) {
    if (is_rrfs_internal(rel_of(from)) || is_rrfs_internal(rel_of(to))) return -EACCES;
    // renameat2 flags: previously silently ignored. RENAME_EXCHANGE would
    // be performed as a plain overwrite (data loss + wrong protection);
    // RENAME_NOREPLACE would clobber the destination. Honour NOREPLACE,
    // refuse everything else explicitly.
    if (flags & ~static_cast<unsigned int>(RENAME_NOREPLACE)) return -EINVAL;
    if (flags & RENAME_NOREPLACE) {
        struct stat st;
        if (lstat(full_path(to).c_str(), &st) == 0) return -EEXIST;
    }
    if (int e = handle_pre_rename(from, to)) return e;
    int res = rename(full_path(from).c_str(), full_path(to).c_str());
    if (res == 0) {
        std::string rf = rel_of(from), rt = rel_of(to);
        if (!g_hold->rekey(rf, rt)) g_hold->drop(rt);   // held file follows its name; a replaced held file is dropped
    }
    return res == -1 ? -errno : 0;
}

int rrfs_mkdir(const char* path, mode_t mode) {
    if (is_rrfs_internal(rel_of(path))) return -EACCES;
    int res = mkdir(full_path(path).c_str(), mode);
    return res == -1 ? -errno : 0;
}

int rrfs_rmdir(const char* path) {
    if (is_rrfs_internal(rel_of(path))) return -EACCES;
    int res = rmdir(full_path(path).c_str());
    return res == -1 ? -errno : 0;
}

int rrfs_chmod(const char* path, mode_t mode, struct fuse_file_info*) {
    if (is_rrfs_internal(rel_of(path))) return -EACCES;
    HoldBack::Access acc(*g_hold, rel_of(path));
    int res = chmod(acc.path().c_str(), mode);
    return res == -1 ? -errno : 0;
}

int rrfs_utimens(const char* path, const struct timespec ts[2], struct fuse_file_info*) {
    if (is_rrfs_internal(rel_of(path))) return -EACCES;
    HoldBack::Access acc(*g_hold, rel_of(path));
    int res = utimensat(AT_FDCWD, acc.path().c_str(), ts, AT_SYMLINK_NOFOLLOW);
    return res == -1 ? -errno : 0;
}

int rrfs_statfs(const char* path, struct statvfs* stbuf) {
    int res = statvfs(full_path(path).c_str(), stbuf);
    return res == -1 ? -errno : 0;
}

bool owner_trusted(long pid, long ppid) {
    double ceiling = g_commit_ceiling_frac * g_anomaly->promote_threshold;
    if (g_amb_policy == 1 && (g_anomaly->ambiguous_hold(pid, g_amb_defer_ms, g_amb_files) ||
                              (ppid > 0 && g_anomaly->ambiguous_hold(ppid, g_amb_defer_ms, g_amb_files)))) return false;
    if (g_cluster_hold && (!g_anomaly->cluster_hold(static_cast<pid_t>(pid), g_cluster_defer_ms).empty() ||
                           (ppid > 0 && !g_anomaly->cluster_hold(static_cast<pid_t>(ppid), g_cluster_defer_ms).empty()))) return false;
    if (g_soft_hold && (g_anomaly->soft_recent(static_cast<pid_t>(pid), std::chrono::milliseconds(g_soft_hold_ms)) ||
                        (ppid > 0 && g_anomaly->soft_recent(static_cast<pid_t>(ppid), std::chrono::milliseconds(g_soft_hold_ms))))) return false;
    if (g_anomaly->current_score(pid) >= ceiling) return false;
    if (ppid > 0 && g_anomaly->current_score(ppid) >= ceiling) return false;
    std::lock_guard<std::mutex> lk(g_blocked_mutex);
    return !g_blocked.count(pid) && !(ppid > 0 && g_blocked.count(ppid));
}

// fsync: an application that asks for durability gets it immediately if the
// writer still looks innocent; otherwise the write stays held back.
int rrfs_fsync(const char* path, int, struct fuse_file_info*) {
    std::string rel = rel_of(path);
    if (!is_rrfs_internal(rel) && g_hold) g_hold->commit_if(rel, owner_trusted);
    return 0;
}

void rrfs_destroy(void*) {
    // Clean unmount: nothing is left uncommitted.
    size_t n = g_hold ? g_hold->commit_all() : 0;
    if (g_events && n) g_events->log("commit", -1, "", -1, -1, "", "unmount: committed " + std::to_string(n) + " held writes");
}

const fuse_operations rrfs_ops = [] {
    fuse_operations ops{};
    ops.getattr = rrfs_getattr;
    ops.readdir = rrfs_readdir;
    ops.open = rrfs_open;
    ops.read = rrfs_read;
    ops.write = rrfs_write;
    ops.create = rrfs_create;
    ops.truncate = rrfs_truncate;
    ops.unlink = rrfs_unlink;
    ops.rename = rrfs_rename;
    ops.mkdir = rrfs_mkdir;
    ops.rmdir = rrfs_rmdir;
    ops.chmod = rrfs_chmod;
    ops.utimens = rrfs_utimens;
    ops.statfs = rrfs_statfs;
    ops.destroy = rrfs_destroy;
    ops.fsync = rrfs_fsync;
    return ops;
}();

void print_usage(const char* prog) {
    fprintf(stderr,
            "usage: %s <backing_dir> <mountpoint> [--config <path>] [fuse options]\n"
            "  backing_dir : real directory that stores the live data\n"
            "  mountpoint  : empty directory to mount rrfs on\n"
            "  --config    : path to a rrfs.conf-style file (default:\n"
            "                <backing_dir>/rrfs.conf if present)\n",
            prog);
}

// Commits held-back writes that have been quiet for commit_delay_ms and whose
// owner (and its parent bucket) still scores well below the threshold.
void commit_thread_main() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        size_t n = g_hold->commit_due(g_commit_delay_ms, owner_trusted);
        n += g_hold->enforce_limit(g_hold_max_files);
        if (n) g_events->log("commit", -1, "", -1, -1, "", "committed " + std::to_string(n) + " held writes");
    }
}

// Periodic baseline checkpoints: if the backing tree has seen any
// write/rename since the last baseline, promote a "scheduled" one
// every `baseline_interval_seconds`. This narrows (does not close --
// see README limitations) the gap where recovery needs a checkpoint
// taken before an attack started: without this, only an operator's
// manual PROMOTE predates an attack, and the worst case is "no
// baseline was ever taken". Disabled when the interval is <= 0.
void baseline_thread_main(int interval_seconds) {
    long long last_seen = g_write_counter.load(std::memory_order_relaxed);
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
        long long now_count = g_write_counter.load(std::memory_order_relaxed);
        if (now_count == last_seen) continue; // nothing written since last baseline
        last_seen = now_count;
        std::string id = g_canary->promote_checkpoint("scheduled", -1, -1);
        if (!id.empty()) {
            g_events->log("promote", -1, "", -1, -1, id, "scheduled baseline checkpoint");
        }
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    g_backing_root = argv[1];
    std::string mountpoint = argv[2];
    std::string config_path = g_backing_root + "/rrfs.conf";

    std::vector<char*> fuse_argv;
    fuse_argv.push_back(argv[0]);
    fuse_argv.push_back(argv[2]);
    for (int i = 3; i < argc; ++i) {
        if (std::string(argv[i]) == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else {
            fuse_argv.push_back(argv[i]);
        }
    }

    Config cfg = Config::load(config_path);

    std::string state_root = g_backing_root + "/.rrfs_state";
    std::string canary_root = state_root + "/canary";
    std::string checkpoint_root = state_root + "/checkpoints";
    std::string events_path = state_root + "/events.log";

    static CanaryManager canary(g_backing_root, canary_root, checkpoint_root,
                                 cfg.get_int("ring_size", 8));
    static AnomalyEngine anomaly;
    static EventLog events(events_path);

    anomaly.w_entropy = cfg.get_double("w_entropy", anomaly.w_entropy);
    anomaly.w_overwrite_burst = cfg.get_double("w_overwrite_burst", anomaly.w_overwrite_burst);
    anomaly.w_ext_churn = cfg.get_double("w_ext_churn", anomaly.w_ext_churn);
    anomaly.entropy_high_water = cfg.get_double("entropy_high_water", anomaly.entropy_high_water);
    anomaly.burst_file_threshold = cfg.get_int("burst_file_threshold", anomaly.burst_file_threshold);
    anomaly.window = std::chrono::seconds(cfg.get_int("window_seconds", 5));
    anomaly.promote_threshold = cfg.get_double("promote_threshold", anomaly.promote_threshold);
    anomaly.decay_per_second = cfg.get_double("decay_per_second", anomaly.decay_per_second);
    g_suspend_on_detect = cfg.get_bool("suspend_on_detect", true);
    canary.set_max_scheduled_checkpoints(cfg.get_int("max_scheduled_checkpoints", 5));
    canary.set_min_promote_interval_ms(cfg.get_int("promote_min_interval_ms", 2000));

    anomaly.w_type_destroyed = cfg.get_double("w_type_destroyed", anomaly.w_type_destroyed);
    anomaly.slow_burn_files = cfg.get_int("slow_burn_files", anomaly.slow_burn_files);
    anomaly.slow_window = std::chrono::seconds(cfg.get_int("slow_window_seconds", 300));
    g_entropy_jump_min = cfg.get_double("entropy_jump_min", g_entropy_jump_min);
    g_aggregate_parent = cfg.get_bool("aggregate_by_parent", true);
    g_graded = cfg.get_bool("graded_response", true);
    g_del_alert = static_cast<int>(cfg.get_int("bulk_delete_alert_files", 16));
    g_log_writes = cfg.get_bool("log_writes", true);
    g_provenance = cfg.get_bool("read_provenance", false);
    g_prov_min_ham = cfg.get_double("provenance_min_hamming", 0.35);
    g_prov_window_ms = cfg.get_int("provenance_window_ms", 120000);
    g_soft_hold = cfg.get_bool("soft_hold", true);
    g_soft_hold_ms = cfg.get_int("soft_hold_ms", 30000);
    g_soft_ckpt = cfg.get_bool("soft_checkpoint", true);
    g_cluster_hold = cfg.get_bool("cluster_hold", true);
    g_cluster_block = cfg.get_bool("cluster_block", false);
    g_cluster_defer_ms = cfg.get_int("cluster_defer_ms", 30000);
    anomaly.cluster_min_files = static_cast<int>(cfg.get_int("cluster_min_files", 8));
    anomaly.cluster_min_pids = static_cast<int>(cfg.get_int("cluster_min_pids", 3));
    anomaly.global_min_files = static_cast<int>(cfg.get_int("global_min_files", 16));
    g_shelve = cfg.get_bool("shelve_on_detect", true);
    g_type_conv_benign = cfg.get_bool("type_conversion_benign", true);
    anomaly.hard_min_content_files = static_cast<int>(cfg.get_int("hard_min_content_files", 2));
    g_content_delta = cfg.get_bool("content_delta_enabled", true);
    { std::string p = cfg.get_string("ambiguous_policy", "defer");
      g_amb_policy = p == "off" ? 0 : p == "freeze" ? 2 : 1; }
    g_amb_files = static_cast<int>(cfg.get_int("ambiguous_files", 8));
    g_amb_defer_ms = cfg.get_int("ambiguous_defer_ms", 30000);
    g_repair_on_detect = cfg.get_bool("repair_on_detect", true);
    g_holdback_enabled = cfg.get_bool("holdback_enabled", true);
    HoldBack::set_fast_copy(cfg.get_bool("holdback_fast_copy", false));
    g_commit_delay_ms = cfg.get_int("holdback_commit_delay_ms", 2000);
    g_hold_max_bytes = static_cast<size_t>(cfg.get_int("holdback_max_file_mb", 64)) << 20;
    g_hold_max_files = static_cast<size_t>(cfg.get_int("holdback_max_files", 256));
    g_commit_ceiling_frac = cfg.get_double("holdback_commit_score_frac", 0.5);
    g_state_root = state_root;
    static HoldBack hold(g_backing_root, state_root + "/pending");
    g_hold = &hold;

    g_canary = &canary;
    g_anomaly = &anomaly;
    g_events = &events;
    g_daemon_uid = getuid();
    g_canary->init();
    {
        size_t stale = g_hold->init();
        g_events->log("write", -1, "", -1, -1, "", "rrfs_fuse started, config=" + config_path +
                       (stale ? " (discarded " + std::to_string(stale) + " stale pending copies from a previous run)" : ""));
    }
    if (g_holdback_enabled) std::thread(commit_thread_main).detach();

    int baseline_interval = cfg.get_int("baseline_interval_seconds", 60);
    if (baseline_interval > 0) {
        std::thread(baseline_thread_main, baseline_interval).detach();
    }

    fprintf(stderr,
            "rrfs: backing=%s mount=%s config=%s promote_threshold=%.2f suspend_on_detect=%s "
            "baseline_interval_s=%d\n",
            g_backing_root.c_str(), mountpoint.c_str(), config_path.c_str(),
            anomaly.promote_threshold, g_suspend_on_detect ? "true" : "false", baseline_interval);

    return fuse_main(static_cast<int>(fuse_argv.size()), fuse_argv.data(), &rrfs_ops, nullptr);
}
