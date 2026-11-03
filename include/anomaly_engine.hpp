#pragma once
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <sys/types.h>

// Per-process anomaly scorer.
//
// Implements the "Multi-Modal Anomaly Engine" from the proposal
// (Slide 15, addressing Gap 1): rather than trusting any single weak
// signal, it fuses three per-write observations into one composite,
// decaying score per PID:
//
//   1. write entropy               (CryptoLock/DaD-style signal)
//   2. distinct-file overwrite burst in a short sliding window
//      (ShieldFS/RWGuard-style behavioral signal)
//   3. file-extension churn        (rename-to-random-extension pattern
//      seen in most cryptographic ransomware families)
//
// Note: the burst term now counts distinct SUSPICIOUS
// paths touched in the window -- a path only counts if that specific
// event was itself high-entropy or an extension change -- instead of
// every write *call* regardless of content. The earlier version
// incremented a raw call counter on every event unconditionally,
// which meant a single large file copied in many small chunks (many
// calls, one path, ordinary content) or a `tar -x` of many small
// plain-text files (many paths, ordinary content) both reached the
// burst threshold and froze the process. Gating burst membership on a
// corroborating per-event signal keeps requiring genuine fusion
// (Gap 1) rather than letting burst alone -- content-blind -- carry
// detection, and an audited regression test (AnomalyEngine_BenignBurst)
// pins this down: a 20-file burst of plain low-entropy writes with no
// renames must NOT cross the default threshold.
//
// The score is what CanaryManager::promote_checkpoint() is triggered
// against once it crosses `promote_threshold`.
class AnomalyEngine {
public:
    // Records one write/rename event for `pid` against `path` and
    // returns the process's updated composite score. `path` is used
    // only to track which DISTINCT paths have had a suspicious event
    // in the current window -- it does not leak elsewhere. Replaces
    // the old `is_new_file_this_window` boolean, which the caller had
    // to compute (and which the FUSE daemon always passed as `true`,
    // the root cause above).
    //
    // `type_changed` (default false) is the content-delta signal: the
    // write destroyed a recognisable file signature or turned text into
    // binary (see content_delta.hpp). It adds w_type_destroyed once per
    // path per window and counts as a corroborating event.
    double record_write(pid_t pid, const std::string& path, double entropy,
                         bool extension_changed, bool type_changed = false);

    double current_score(pid_t pid);

    // --- graded response. A threshold crossing driven ONLY by namespace/extension events (no
    // distinct files carrying content evidence: high entropy or destroyed type/text) is a SOFT
    // detection: it is logged and checkpointed but nobody is stopped. A HARD detection needs
    // content evidence on at least `hard_min_content_files` distinct files within slow_window.
    int content_files(pid_t pid);
    // --- cooperation-aware / cumulative HOLD tier. Content-evidence events are also
    // accumulated per cluster key (the writer's executable, and the global key "*"). A cluster that reaches
    // `files` distinct evidence files from at least `pids` distinct processes inside slow_window makes ALL its
    // members' held writes un-committable for defer_ms after the last evidence. Hold-only: nobody is stopped.
    int note_cluster(const std::string& key, pid_t pid, const std::string& path);   // returns distinct live paths
    // Name of the cluster whose hold covers `pid` right now ("" if none).
    std::string cluster_hold(pid_t pid, long long defer_ms);
    int cluster_min_files = 8;
    int cluster_min_pids = 3;
    int global_min_files = 16;
    // Rate-limits soft alerts: returns true at most once per `cooldown` per pid.
    bool soft_alert_due(pid_t pid, std::chrono::seconds cooldown);
    bool soft_recent(pid_t pid, std::chrono::milliseconds window);   // a soft alert was raised for this key within `window`
    void reset(pid_t pid);

    // --- Destructive-vs-creative write tracking (added after the
    // false-positive finding on bulk copies of already-compressed data).
    // Writing high-entropy bytes into a file that held NO prior data
    // (new file / append past EOF) destroys nothing and is what every
    // benign copy, download, archive-extract and compress does. Only
    // writes that overwrite or truncate EXISTING bytes are scored.
    // The fuse layer reports the other cases here so replace-style
    // attacks (write ciphertext elsewhere, then rename-over or delete
    // the original) are still caught:
    void note_fresh_high_entropy(pid_t pid, const std::string& path); // no score
    bool take_fresh_high_entropy(pid_t pid, const std::string& path); // consume
    bool has_fresh_high_entropy(pid_t pid);
    // A fresh file whose first bytes carry a recognised file signature (a
    // JPEG/archive copy or download) is benign output, not ciphertext: it
    // is remembered as "typed" and never feeds the replace/delete signals.
    void note_typed_fresh(pid_t pid, const std::string& path);
    // Files this process created itself (temp files). A rename of such a
    // file to its final name is the ordinary "save via temp file" pattern.
    void note_created(pid_t pid, const std::string& path);
    bool take_created(pid_t pid, const std::string& path);
    bool is_created(pid_t pid, const std::string& path);      // non-consuming
    // Ambiguous destructive writes: high-entropy bytes replaced by high-entropy
    // bytes with no content-delta evidence (the documented blind spot). They are
    // counted separately; what to do about them is a policy decision of the caller.
    // Returns the number of DISTINCT ambiguous files within slow_window.
    int note_ambiguous(pid_t pid, const std::string& path);
    // True while `pid` has >= min_files distinct ambiguous files and the most recent
    // one is younger than defer_ms (the caller then withholds commit of its held writes).
    bool ambiguous_hold(pid_t pid, long long defer_ms, int min_files);
    void mark_destroyed(pid_t pid, const std::string& path);   // O_TRUNC'd existing data
    bool is_destroyed(pid_t pid, const std::string& path);

    // Tunable weights/threshold. Exposed as public fields so they can
    // be swept experimentally (e.g. from a config file or CLI flags)
    // rather than hard-coded assumptions baked into the algorithm.
    double w_entropy = 1.0;
    double w_overwrite_burst = 2.0;
    double w_ext_churn = 3.0;
    double w_type_destroyed = 3.0;       // content-delta: signature/text destroyed
    // Slow-burn signal (rate-independent): this many DISTINCT corroborated
    // paths within slow_window forces a detection regardless of pacing.
    int slow_burn_files = 8;
    int hard_min_content_files = 2;       // distinct content-evidence files required for a hard (freezing) detection
    std::chrono::seconds slow_window{300};
    double entropy_high_water = 7.5;     // bits/byte considered "high"
    int burst_file_threshold = 6;        // distinct SUSPICIOUS files/window to flag a burst
    std::chrono::seconds window{5};      // sliding window for burst detection
    double promote_threshold = 10.0;     // composite score that triggers a checkpoint
    double decay_per_second = 0.5;       // score cools down when a process goes quiet

private:
    struct ProcState {
        double score = 0.0;
        std::unordered_set<std::string> suspicious_paths_in_window;
        std::unordered_set<std::string> typed_paths_in_window;  // type_changed counted once per path/window
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> slow_paths;
        bool slow_fired = false;
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> content_paths;
        std::chrono::steady_clock::time_point soft_last{};
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> amb_paths;
        std::chrono::steady_clock::time_point amb_last{};
        std::unordered_set<std::string> fresh_high_paths;   // capped (kMaxTracked)
        std::unordered_set<std::string> typed_fresh_paths;  // capped
        std::unordered_set<std::string> created_paths;      // capped
        std::unordered_set<std::string> destroyed_paths;    // capped (kMaxTracked)
        std::chrono::steady_clock::time_point window_start{};
        std::chrono::steady_clock::time_point last_update{};
    };

    struct Cluster {
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> paths;
        std::unordered_set<pid_t> pids;
        std::chrono::steady_clock::time_point last{};
    };
    std::unordered_map<std::string, Cluster> clusters_;
    static constexpr size_t kMaxTracked = 4096;
    std::mutex mu_;
    std::unordered_map<pid_t, ProcState> procs_;

    void decay_locked(ProcState& s, std::chrono::steady_clock::time_point now);
    void maybe_roll_window_locked(ProcState& s, std::chrono::steady_clock::time_point now);
};
