#include "canary_manager.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace {

std::string join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

void remove_tree(const std::string& path) {
    DIR* d = opendir(path.c_str());
    if (!d) {
        unlink(path.c_str());
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string full = join(path, name);
        struct stat st{};
        if (lstat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            remove_tree(full);
        } else {
            unlink(full.c_str());
        }
    }
    closedir(d);
    // Directory may currently be read-only (checkpoints are chmod 0555);
    // restore write perms on the dir itself so rmdir succeeds.
    chmod(path.c_str(), 0755);
    rmdir(path.c_str());
}

long long now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

// Non-throwing by design (audit finding: an earlier version threw
// std::runtime_error on an unreadable source file, which is uncaught
// exception risk when invoked from a libfuse worker thread and would
// abort the whole daemon). Returns false and leaves `dst` untouched
// on any I/O failure; callers skip that one file and continue, which
// is the right failure mode for a best-effort protection layer.
bool CanaryManager::copy_file(const std::string& src, const std::string& dst) {
    struct stat st{};
    if (stat(src.c_str(), &st) != 0) return false;

    std::ifstream in(src, std::ios::binary);
    if (!in) return false;
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << in.rdbuf();
    if (!out) return false;
    in.close();
    out.close();
    chmod(dst.c_str(), st.st_mode & 07777);
    return true;
}

void CanaryManager::ensure_dir(const std::string& path) {
    std::string cur;
    std::stringstream ss(path);
    std::string part;
    if (!path.empty() && path.front() == '/') cur = "/";
    while (std::getline(ss, part, '/')) {
        if (part.empty()) continue;
        cur = join(cur, part);
        mkdir(cur.c_str(), 0755); // ignore EEXIST
    }
}

void CanaryManager::copy_tree(const std::string& src, const std::string& dst) {
    struct stat st{};
    if (stat(src.c_str(), &st) != 0) return;
    ensure_dir(dst);

    DIR* d = opendir(src.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        // Never recurse into rrfs' own bookkeeping directory when
        // snapshotting the live tree -- checkpoints/canary state
        // should not nest a copy of themselves.
        if (name == ".rrfs_state") continue;
        std::string s = join(src, name);
        std::string t = join(dst, name);
        struct stat est{};
        if (lstat(s.c_str(), &est) != 0) continue;
        if (S_ISDIR(est.st_mode)) {
            ensure_dir(t);
            copy_tree(s, t);
        } else if (S_ISREG(est.st_mode)) {
            copy_file(s, t); // best-effort; see copy_file() doc comment
        }
    }
    closedir(d);
}

void CanaryManager::write_meta(const std::string& checkpoint_dir, const CheckpointInfo& info) {
    std::ofstream out(join(checkpoint_dir, "meta.json"));
    if (!out) return;
    out << "{"
        << "\"id\":\"" << info.id << "\","
        << "\"timestamp_ms\":" << info.timestamp_ms << ","
        << "\"reason\":\"" << info.reason << "\","
        << "\"trigger_pid\":" << info.trigger_pid << ","
        << "\"trigger_score\":" << info.trigger_score
        << "}\n";
}

bool CanaryManager::read_meta(const std::string& checkpoint_dir, CheckpointInfo& info) {
    std::ifstream in(join(checkpoint_dir, "meta.json"));
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string s = ss.str();

    auto extract_str = [&](const std::string& key) -> std::string {
        auto p = s.find("\"" + key + "\":\"");
        if (p == std::string::npos) return "";
        p += key.size() + 4;
        auto e = s.find('"', p);
        return e == std::string::npos ? "" : s.substr(p, e - p);
    };
    auto extract_num = [&](const std::string& key) -> double {
        auto p = s.find("\"" + key + "\":");
        if (p == std::string::npos) return 0;
        p += key.size() + 3;
        return std::atof(s.c_str() + p);
    };

    info.id = extract_str("id");
    info.timestamp_ms = static_cast<long long>(extract_num("timestamp_ms"));
    info.reason = extract_str("reason");
    info.trigger_pid = static_cast<long>(extract_num("trigger_pid"));
    info.trigger_score = extract_num("trigger_score");
    return true;
}

CanaryManager::CanaryManager(std::string backing_root, std::string canary_root,
                              std::string checkpoint_root, int ring_size)
    : backing_root_(std::move(backing_root)),
      canary_root_(std::move(canary_root)),
      checkpoint_root_(std::move(checkpoint_root)),
      ring_size_(ring_size) {}

void CanaryManager::init() {
    ensure_dir(backing_root_);
    ensure_dir(canary_root_);
    ensure_dir(checkpoint_root_);
    ensure_dir(current_generation_dir());
}

void CanaryManager::set_min_promote_interval_ms(long ms) {
    std::lock_guard<std::mutex> lk(mu_);
    min_promote_interval_ms_ = ms;
}

std::string CanaryManager::current_generation_dir() const {
    return join(canary_root_, "gen_" + std::to_string(generation_));
}

void CanaryManager::protect_before_write(const std::string& rel_path) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string gen_dir = current_generation_dir();
    std::string canary_copy = join(gen_dir, rel_path);

    struct stat st{};
    if (stat(canary_copy.c_str(), &st) == 0) {
        return; // already protected in this generation
    }

    std::string live = join(backing_root_, rel_path);
    struct stat live_st{};
    if (stat(live.c_str(), &live_st) != 0) {
        return; // file didn't exist yet -- nothing to preserve
    }
    if (!S_ISREG(live_st.st_mode)) {
        return; // only regular files are protected (symlinks/devices: see README limitations)
    }

    auto pos = canary_copy.find_last_of('/');
    if (pos != std::string::npos) {
        ensure_dir(canary_copy.substr(0, pos));
    }
    copy_file(live, canary_copy); // best-effort; never throws (see copy_file doc comment)
}

void CanaryManager::record_rename(const std::string& from, const std::string& to,
                                  bool dest_preexisted) {
    std::lock_guard<std::mutex> lk(mu_);
    // A pre-existing destination keeps its canary copy (original bytes);
    // only destinations that did not exist before are erased from the
    // reconstruction. Chains through a rename-over still work: the
    // chain's intermediate names are new files.
    if (!dest_preexisted) renames_seen_.emplace_back(from, to);
}

std::string CanaryManager::oldest_copy_locked(const std::string& rel) const {
    for (long g = 0; g <= generation_; ++g) {
        std::string c = join(join(canary_root_, "gen_" + std::to_string(g)), rel);
        struct stat st{};
        if (stat(c.c_str(), &st) == 0 && S_ISREG(st.st_mode)) return c;
    }
    return "";
}

std::string CanaryManager::oldest_copy(const std::string& rel) {
    std::lock_guard<std::mutex> lk(mu_);
    return oldest_copy_locked(rel);
}

int CanaryManager::repair_path(const std::string& rel, bool existed_before,
                               const std::string& quarantine_dir) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string live = join(backing_root_, rel);

    // Oldest surviving copy wins, as in auto-checkpoint reconstruction.
    std::string copy = oldest_copy_locked(rel);
    struct stat lst{};
    bool live_exists = lstat(live.c_str(), &lst) == 0;
    if (existed_before) {
        if (copy.empty()) return 0;                       // cannot restore: leave live alone
        if (live_exists && files_identical(live, copy)) return 0;  // nothing to undo
    } else if (!live_exists) {
        return 0;
    }
    if (live_exists) {                                     // quarantine, never delete
        std::string q = join(quarantine_dir, rel);
        auto pos = q.find_last_of('/');
        if (pos != std::string::npos) ensure_dir(q.substr(0, pos));
        if (rename(live.c_str(), q.c_str()) != 0) return 0;
    }
    if (!existed_before) return 2;
    auto pos = live.find_last_of('/');
    if (pos != std::string::npos) ensure_dir(live.substr(0, pos));
    return copy_file(copy, live) ? 1 : 0;
}

bool CanaryManager::unrepair_path(const std::string& rel, const std::string& quarantine_dir, const std::string& undo_dir) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string live = join(backing_root_, rel), q = join(quarantine_dir, rel);
    struct stat st{};
    if (lstat(q.c_str(), &st) != 0) return false;
    if (lstat(live.c_str(), &st) == 0) {
        std::string u = join(undo_dir, rel);
        auto pos = u.find_last_of('/');
        if (pos != std::string::npos) ensure_dir(u.substr(0, pos));
        if (rename(live.c_str(), u.c_str()) != 0) return false;
    }
    auto pos = live.find_last_of('/');
    if (pos != std::string::npos) ensure_dir(live.substr(0, pos));
    return rename(q.c_str(), live.c_str()) == 0;
}

void CanaryManager::rotate_ring_locked() {
    generation_++;
    ensure_dir(current_generation_dir());

    long oldest_to_keep = generation_ - ring_size_;
    for (long g = oldest_to_keep - 1; g >= 0; --g) {
        std::string old_dir = join(canary_root_, "gen_" + std::to_string(g));
        struct stat st{};
        if (stat(old_dir.c_str(), &st) == 0) {
            remove_tree(old_dir);
        } else {
            break;
        }
    }
}

void CanaryManager::prune_scheduled_locked() {
    if (max_scheduled_ <= 0) return;
    std::vector<CheckpointInfo> sched;
    for (auto& c : list_checkpoints()) if (c.reason == "scheduled") sched.push_back(c);
    // list_checkpoints() is oldest-first.
    while (static_cast<int>(sched.size()) > max_scheduled_) {
        std::string dir = join(checkpoint_root_, sched.front().id);
        chmod(dir.c_str(), 0755);   // checkpoints are 0555; unlink needs write on the dir
        remove_tree(dir);
        sched.erase(sched.begin());
    }
}

void CanaryManager::build_auto_checkpoint_locked(const std::string& checkpoint_dir) {
    // relpath -> absolute source path to copy from. Seeded from the
    // live tree (lowest priority: used only where no canary copy of
    // that path exists anywhere in the still-present ring).
    std::unordered_map<std::string, std::string> src_for;
    std::vector<std::string> live_files;
    collect_files(backing_root_, "", live_files);
    for (auto& f : live_files) src_for[f] = join(backing_root_, f);

    // Overlay canary generations from NEWEST to OLDEST, unconditionally
    // overwriting each path's source as we go. Because the OLDEST
    // generation is applied LAST, its copy -- the one closest to the
    // pre-attack state -- wins for any path it contains, including
    // paths the live tree no longer has under their original name
    // (e.g. the attacker renamed doc.txt to doc.txt.locked: the
    // canary copy of "doc.txt" restores it under its original name).
    for (long g = generation_; g >= 0; --g) {
        std::string gdir = join(canary_root_, "gen_" + std::to_string(g));
        struct stat st{};
        if (stat(gdir.c_str(), &st) != 0) continue; // pruned or never created
        std::vector<std::string> gen_files;
        collect_files(gdir, "", gen_files);
        for (auto& f : gen_files) src_for[f] = join(gdir, f);
    }

    // Drop every recorded rename DESTINATION, as a FINAL pass after
    // both the live seed and the canary overlay. Without this, a
    // renamed file could appear TWICE: once under its new name
    // (seeded from live and/or re-protected by a later rename in a
    // chain, still damaged) and once under its original name (the
    // canary overlay above, restored) -- both present at once. This
    // runs last specifically because a rename CHAIN (a->b->c) can
    // cause an intermediate name ("b") to pick up its own canary copy
    // from the second hop's protect_before_write(to) call, which an
    // erase-before-overlay ordering would miss; erasing after the
    // overlay removes it regardless of which step re-introduced it,
    // leaving only the earliest name, "a", in the reconstruction.
    for (auto& fromto : renames_seen_) {
        src_for.erase(fromto.second);
    }

    ensure_dir(checkpoint_dir);
    for (auto& kv : src_for) {
        const std::string& relpath = kv.first;
        const std::string& src = kv.second;
        std::string dst = join(checkpoint_dir, relpath);
        auto pos = dst.find_last_of('/');
        if (pos != std::string::npos) ensure_dir(dst.substr(0, pos));
        copy_file(src, dst); // best-effort; never throws
    }
}

std::string CanaryManager::promote_checkpoint(const std::string& reason, long trigger_pid,
                                               double trigger_score) {
    std::lock_guard<std::mutex> lk(mu_);

    if (min_promote_interval_ms_ > 0) {
        auto now = std::chrono::steady_clock::now();
        if (last_promote_time_.time_since_epoch().count() != 0) {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   now - last_promote_time_)
                                   .count();
            if (elapsed_ms < min_promote_interval_ms_) {
                return ""; // rate-limited: caller must check for an empty id
            }
        }
    }

    long long ts = now_millis();
    std::string checkpoint_id = "ckpt_" + std::to_string(ts) + "_gen" +
                                 std::to_string(generation_);
    std::string checkpoint_dir = join(checkpoint_root_, checkpoint_id);

    if (reason == "auto" || reason == "cluster" || reason == "soft") {   // rebuilt from the ring: originals, not the post-damage tree
        build_auto_checkpoint_locked(checkpoint_dir);
    } else {
        copy_tree(backing_root_, checkpoint_dir);
    }

    CheckpointInfo info;
    info.id = checkpoint_id;
    info.timestamp_ms = ts;
    info.reason = reason;
    info.trigger_pid = trigger_pid;
    info.trigger_score = trigger_score;
    write_meta(checkpoint_dir, info);

    // Mark read-only at the directory level (best-effort in this
    // prototype; a kernel-native version would use an
    // immutable/append-only attribute).
    chmod(checkpoint_dir.c_str(), 0555);

    rotate_ring_locked();
    if (reason == "scheduled") prune_scheduled_locked();
    last_promote_time_ = std::chrono::steady_clock::now();
    return checkpoint_id;
}

bool CanaryManager::rollback(const std::string& checkpoint_id) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string checkpoint_dir = join(checkpoint_root_, checkpoint_id);
    struct stat st{};
    if (stat(checkpoint_dir.c_str(), &st) != 0) {
        return false;
    }

    std::string staging = backing_root_ + ".rrfs_staging";
    remove_tree(staging);
    copy_tree(checkpoint_dir, staging);
    chmod(staging.c_str(), 0755);

    std::string trash = backing_root_ + ".rrfs_trash";
    remove_tree(trash);

    if (rename(backing_root_.c_str(), trash.c_str()) != 0) {
        remove_tree(staging);
        return false;
    }
    if (rename(staging.c_str(), backing_root_.c_str()) != 0) {
        rename(trash.c_str(), backing_root_.c_str());
        return false;
    }

    // Preserve rrfs' own bookkeeping directory across the swap --
    // checkpoints/canary state live outside the snapshotted tree.
    std::string old_state = join(trash, ".rrfs_state");
    std::string new_state = join(backing_root_, ".rrfs_state");
    struct stat state_st{};
    if (stat(old_state.c_str(), &state_st) == 0 && stat(new_state.c_str(), &state_st) != 0) {
        rename(old_state.c_str(), new_state.c_str());
    }

    remove_tree(trash);
    return true;
}

std::vector<CanaryManager::CheckpointInfo> CanaryManager::list_checkpoints() const {
    std::vector<CheckpointInfo> out;
    DIR* d = opendir(checkpoint_root_.c_str());
    if (!d) return out;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        CheckpointInfo info;
        info.id = name;
        std::string dir = join(checkpoint_root_, name);
        if (!read_meta(dir, info)) {
            info.reason = "unknown";
        }
        out.push_back(info);
    }
    closedir(d);
    std::sort(out.begin(), out.end(),
              [](const CheckpointInfo& a, const CheckpointInfo& b) {
                  return a.timestamp_ms < b.timestamp_ms;
              });
    return out;
}

void CanaryManager::collect_files(const std::string& root, const std::string& prefix,
                                   std::vector<std::string>& out) {
    DIR* d = opendir(root.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        if (prefix.empty() && name == ".rrfs_state") continue; // never diff/reconstruct bookkeeping
        std::string full = join(root, name);
        std::string relpath = prefix.empty() ? name : prefix + "/" + name;
        struct stat st{};
        if (lstat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            collect_files(full, relpath, out);
        } else if (S_ISREG(st.st_mode)) {
            out.push_back(relpath);
        }
    }
    closedir(d);
}

bool CanaryManager::files_identical(const std::string& a, const std::string& b) {
    struct stat sa{}, sb{};
    if (stat(a.c_str(), &sa) != 0 || stat(b.c_str(), &sb) != 0) return false;
    if (sa.st_size != sb.st_size) return false;

    std::ifstream fa(a, std::ios::binary);
    std::ifstream fb(b, std::ios::binary);
    if (!fa || !fb) return false;

    constexpr size_t kBufSize = 65536;
    std::vector<char> bufa(kBufSize), bufb(kBufSize);
    while (fa && fb) {
        fa.read(bufa.data(), kBufSize);
        fb.read(bufb.data(), kBufSize);
        std::streamsize na = fa.gcount();
        std::streamsize nb = fb.gcount();
        if (na != nb) return false;
        if (na == 0) break;
        if (std::memcmp(bufa.data(), bufb.data(), static_cast<size_t>(na)) != 0) return false;
    }
    return true;
}

CanaryManager::DiffResult CanaryManager::diff_against(const std::string& checkpoint_id) const {
    DiffResult result;
    std::string checkpoint_dir = join(checkpoint_root_, checkpoint_id);
    struct stat st{};
    if (stat(checkpoint_dir.c_str(), &st) != 0) {
        return result; // unknown checkpoint -- caller should check list_checkpoints() first
    }

    std::vector<std::string> live_files, ckpt_files;
    collect_files(backing_root_, "", live_files);
    collect_files(checkpoint_dir, "", ckpt_files);

    // meta.json is the checkpoint's own bookkeeping file (written by
    // promote_checkpoint), not part of the snapshotted content -- the
    // live tree never has one, so leaving it in would show up as a
    // false "removed" entry on every diff.
    ckpt_files.erase(std::remove(ckpt_files.begin(), ckpt_files.end(), "meta.json"),
                      ckpt_files.end());

    std::sort(live_files.begin(), live_files.end());
    std::sort(ckpt_files.begin(), ckpt_files.end());

    size_t i = 0, j = 0;
    while (i < live_files.size() || j < ckpt_files.size()) {
        if (j >= ckpt_files.size() || (i < live_files.size() && live_files[i] < ckpt_files[j])) {
            result.added.push_back(live_files[i]);
            ++i;
        } else if (i >= live_files.size() || ckpt_files[j] < live_files[i]) {
            result.removed.push_back(ckpt_files[j]);
            ++j;
        } else {
            std::string live_path = join(backing_root_, live_files[i]);
            std::string ckpt_path = join(checkpoint_dir, ckpt_files[j]);
            if (files_identical(live_path, ckpt_path)) {
                result.unchanged.push_back(live_files[i]);
            } else {
                result.modified.push_back(live_files[i]);
            }
            ++i;
            ++j;
        }
    }
    return result;
}

std::string CanaryManager::format_diff(const DiffResult& diff) {
    std::ostringstream ss;
    ss << "modified (" << diff.modified.size() << "):\n";
    for (auto& f : diff.modified) ss << "  ~ " << f << "\n";
    ss << "added since checkpoint (" << diff.added.size() << "):\n";
    for (auto& f : diff.added) ss << "  + " << f << "\n";
    ss << "removed since checkpoint / would reappear on rollback (" << diff.removed.size() << "):\n";
    for (auto& f : diff.removed) ss << "  - " << f << "\n";
    ss << "unchanged: " << diff.unchanged.size() << " file(s)\n";
    return ss.str();
}
