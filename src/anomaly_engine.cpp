#include "anomaly_engine.hpp"
#include <algorithm>

using clk = std::chrono::steady_clock;

void AnomalyEngine::decay_locked(ProcState& s, clk::time_point now) {
    if (s.last_update.time_since_epoch().count() == 0) {
        s.last_update = now;
        return;
    }
    double elapsed = std::chrono::duration<double>(now - s.last_update).count();
    s.score = std::max(0.0, s.score - decay_per_second * elapsed);
    s.last_update = now;
}

void AnomalyEngine::maybe_roll_window_locked(ProcState& s, clk::time_point now) {
    if (s.window_start.time_since_epoch().count() == 0) {
        s.window_start = now;
        return;
    }
    if (now - s.window_start > window) {
        s.suspicious_paths_in_window.clear();
        s.typed_paths_in_window.clear();
        s.window_start = now;
    }
}

double AnomalyEngine::record_write(pid_t pid, const std::string& path, double entropy,
                                    bool extension_changed, bool type_changed) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& s = procs_[pid];
    auto now = clk::now();

    decay_locked(s, now);
    maybe_roll_window_locked(s, now);

    bool high_entropy = entropy >= entropy_high_water;
    // A path only counts toward the burst term if THIS event carried
    // its own corroborating signal -- an ordinary low-entropy write
    // with no rename never makes a path "suspicious", no matter how
    // many distinct files a process touches.
    bool suspicious_event = high_entropy || extension_changed || type_changed;
    if (suspicious_event) {
        s.suspicious_paths_in_window.insert(path);
    }

    double contribution = 0.0;
    if (high_entropy) {
        contribution += w_entropy * (entropy - entropy_high_water);
    }
    if (static_cast<int>(s.suspicious_paths_in_window.size()) >= burst_file_threshold) {
        contribution += w_overwrite_burst;
    }
    if (extension_changed) {
        contribution += w_ext_churn;
    }
    if (type_changed && s.typed_paths_in_window.insert(path).second) {
        contribution += w_type_destroyed;
    }

    if (high_entropy || type_changed) {
        s.content_paths[path] = now;
        for (auto it = s.content_paths.begin(); it != s.content_paths.end();) {
            if (now - it->second > slow_window) it = s.content_paths.erase(it);
            else ++it;
        }
    }

    // Slow-burn: distinct corroborated paths over a LONG window, with no
    // rate decay, so pacing below the burst/decay thresholds does not help.
    if (suspicious_event) {
        s.slow_paths[path] = now;
        for (auto it = s.slow_paths.begin(); it != s.slow_paths.end();) {
            if (now - it->second > slow_window) it = s.slow_paths.erase(it);
            else ++it;
        }
        if (!s.slow_fired && slow_burn_files > 0 &&
            static_cast<int>(s.slow_paths.size()) >= slow_burn_files) {
            s.slow_fired = true;
            contribution += promote_threshold;   // force a detection
        }
    }

    s.score += contribution;
    return s.score;
}

double AnomalyEngine::current_score(pid_t pid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    if (it == procs_.end()) return 0.0;
    decay_locked(it->second, clk::now());
    return it->second.score;
}

void AnomalyEngine::reset(pid_t pid) {
    std::lock_guard<std::mutex> lk(mu_);
    procs_.erase(pid);
}

void AnomalyEngine::note_fresh_high_entropy(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& s = procs_[pid];
    if (s.typed_fresh_paths.count(path)) return;
    if (s.fresh_high_paths.size() < kMaxTracked) s.fresh_high_paths.insert(path);
}

void AnomalyEngine::note_typed_fresh(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& s = procs_[pid];
    s.fresh_high_paths.erase(path);
    if (s.typed_fresh_paths.size() < kMaxTracked) s.typed_fresh_paths.insert(path);
}

void AnomalyEngine::note_created(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& s = procs_[pid];
    if (s.created_paths.size() < kMaxTracked) s.created_paths.insert(path);
}

bool AnomalyEngine::take_created(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    return it != procs_.end() && it->second.created_paths.erase(path) > 0;
}

bool AnomalyEngine::take_fresh_high_entropy(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    return it != procs_.end() && it->second.fresh_high_paths.erase(path) > 0;
}

bool AnomalyEngine::has_fresh_high_entropy(pid_t pid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    return it != procs_.end() && !it->second.fresh_high_paths.empty();
}

void AnomalyEngine::mark_destroyed(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& s = procs_[pid];
    if (s.destroyed_paths.size() < kMaxTracked) s.destroyed_paths.insert(path);
}

bool AnomalyEngine::is_destroyed(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    return it != procs_.end() && it->second.destroyed_paths.count(path) > 0;
}

int AnomalyEngine::note_ambiguous(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = std::chrono::steady_clock::now();
    auto& s = procs_[pid];
    for (auto it = s.amb_paths.begin(); it != s.amb_paths.end();)
        it = (now - it->second > slow_window) ? s.amb_paths.erase(it) : std::next(it);
    if (s.amb_paths.size() < kMaxTracked) s.amb_paths[path] = now;
    s.amb_last = now;
    return static_cast<int>(s.amb_paths.size());
}

bool AnomalyEngine::ambiguous_hold(pid_t pid, long long defer_ms, int min_files) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    if (it == procs_.end()) return false;
    auto& s = it->second;
    if (static_cast<int>(s.amb_paths.size()) < min_files) return false;
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - s.amb_last).count() < defer_ms;
}

bool AnomalyEngine::is_created(pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    return it != procs_.end() && it->second.created_paths.count(path) > 0;
}

int AnomalyEngine::content_files(pid_t pid) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    if (it == procs_.end()) return 0;
    auto now = clk::now();
    int n = 0;
    for (auto& kv : it->second.content_paths) if (now - kv.second <= slow_window) ++n;
    return n;
}

bool AnomalyEngine::soft_alert_due(pid_t pid, std::chrono::seconds cooldown) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& s = procs_[pid];
    auto now = clk::now();
    if (s.soft_last.time_since_epoch().count() != 0 && now - s.soft_last < cooldown) return false;
    s.soft_last = now;
    return true;
}

bool AnomalyEngine::soft_recent(pid_t pid, std::chrono::milliseconds window) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = procs_.find(pid);
    if (it == procs_.end() || it->second.soft_last.time_since_epoch().count() == 0) return false;
    return clk::now() - it->second.soft_last < window;
}

int AnomalyEngine::note_cluster(const std::string& key, pid_t pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = clk::now();
    auto& c = clusters_[key];
    for (auto it = c.paths.begin(); it != c.paths.end();)
        it = (now - it->second > slow_window) ? c.paths.erase(it) : std::next(it);
    if (c.paths.empty()) c.pids.clear();
    if (c.paths.size() < kMaxTracked) c.paths[path] = now;
    if (c.pids.size() < kMaxTracked) c.pids.insert(pid);
    c.last = now;
    if (clusters_.size() > 256) {                        // bound memory: drop idle clusters
        for (auto it = clusters_.begin(); it != clusters_.end();)
            it = (now - it->second.last > slow_window) ? clusters_.erase(it) : std::next(it);
    }
    auto f = clusters_.find(key);
    return f == clusters_.end() ? 0 : static_cast<int>(f->second.paths.size());
}

std::string AnomalyEngine::cluster_hold(pid_t pid, long long defer_ms) {
    std::lock_guard<std::mutex> lk(mu_);
    auto now = clk::now();
    for (auto& kv : clusters_) {
        auto& c = kv.second;
        if (!c.pids.count(pid)) continue;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - c.last).count() >= defer_ms) continue;
        size_t live = 0;
        for (auto& p : c.paths) if (now - p.second <= slow_window) ++live;
        bool global = kv.first == "*";
        if (global ? static_cast<int>(live) >= global_min_files
                   : (static_cast<int>(live) >= cluster_min_files && static_cast<int>(c.pids.size()) >= cluster_min_pids))
            return kv.first;
    }
    return "";
}
