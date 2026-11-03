#pragma once
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

// Append-only JSON-Lines event log: one compact JSON object per line.
// Used both for the live `.rrfs_status` view and for post-hoc analysis
// (e.g. plotting anomaly score over time for a report, matching the
// kind of overhead/latency measurement your literature review cites
// from van Sloun et al., NDSS 2025).
//
// Deliberately hand-rolled instead of using a JSON library: every
// field is a known scalar, so a tiny escaping helper is sufficient
// and keeps the dependency footprint at zero.
class EventLog {
public:
    explicit EventLog(std::string path);

    // type: "write" | "detect" | "promote" | "rollback" | "suspend" | "resume"
    // Any of pid/path/entropy/score/checkpoint_id/detail may be left
    // at their default (0 / empty) when not applicable to this event.
    void log(const std::string& type, long pid = -1, const std::string& path = "",
              double entropy = -1.0, double score = -1.0,
              const std::string& checkpoint_id = "", const std::string& detail = "");

    // Returns the last `n` raw JSON lines (oldest first), for display
    // in `.rrfs_status` or `rrfs_ctl watch`.
    std::vector<std::string> tail(int n) const;

private:
    std::string path_;
    std::ofstream out_;     // kept open: the log is written on every FUSE write, reopening per event was a hot-path cost
    mutable std::mutex mu_;
};
