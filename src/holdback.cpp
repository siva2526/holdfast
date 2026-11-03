#include <atomic>
#include <sys/ioctl.h>
#include <linux/fs.h>
#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif
#include "holdback.hpp"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <map>
#include <tuple>
#include <vector>

long long HoldBack::now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

HoldBack::HoldBack(std::string backing_root, std::string pending_root)
    : backing_(std::move(backing_root)), pending_root_(std::move(pending_root)) {}

HoldBack::Access::Access(HoldBack& hb, const std::string& rel) : lk_(hb.mu_) {
    auto it = hb.held_.find(rel);
    if (it != hb.held_.end() && !it->second.h.shelved) { path_ = it->second.pending; held_ = true; }
    else path_ = hb.backing_ + "/" + rel;
}

size_t HoldBack::init() {
    mkdir(pending_root_.c_str(), 0700);
    // Shelved copies (writes of a process that was flagged) are recorded in a manifest so that an operator can
    // still release or discard them after a daemon restart. Every other leftover pending file is discarded:
    // the backing store still holds the ORIGINAL data, which is the conservative state.
    std::map<std::string, std::tuple<std::string, long, long>> keep;   // pending file name -> (rel, pid, ppid)
    {
        std::ifstream in(pending_root_ + "/shelf.manifest");
        std::string line;
        while (std::getline(in, line)) {
            std::istringstream ls(line);
            std::string name, rel, pid, ppid;
            if (!std::getline(ls, name, '\t') || !std::getline(ls, pid, '\t') || !std::getline(ls, ppid, '\t') || !std::getline(ls, rel)) continue;
            struct stat st{};
            if (stat((pending_root_ + "/" + name).c_str(), &st) != 0) continue;
            keep[name] = std::make_tuple(rel, std::atol(pid.c_str()), std::atol(ppid.c_str()));
        }
    }
    size_t n = 0;
    if (DIR* d = opendir(pending_root_.c_str())) {
        while (dirent* e = readdir(d)) {
            std::string name = e->d_name;
            if (name == "." || name == ".." || name == "shelf.manifest") continue;
            if (keep.count(name)) continue;
            unlink((pending_root_ + "/" + name).c_str());
            ++n;
        }
        closedir(d);
    }
    std::unique_lock<std::shared_mutex> lk(mu_);
    for (auto& kv : keep) {
        Entry e;
        e.h.rel = std::get<0>(kv.second); e.h.owner_pid = std::get<1>(kv.second); e.h.owner_ppid = std::get<2>(kv.second);
        e.h.last_write_ms = e.h.held_since_ms = now_ms();
        e.h.shelved = true;
        e.pending = pending_root_ + "/" + kv.first;
        held_[e.h.rel] = std::move(e);
        long id = std::atol(kv.first.c_str() + (kv.first.size() > 1 ? 1 : 0));
        if (id >= static_cast<long>(next_id_)) next_id_ = static_cast<decltype(next_id_)>(id + 1);
        ++recovered_;
    }
    persist_shelf_locked();
    return n;
}

void HoldBack::persist_shelf_locked() {
    std::string tmp = pending_root_ + "/shelf.manifest.tmp", fin = pending_root_ + "/shelf.manifest";
    size_t cnt = 0;
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return;
        for (auto& kv : held_) {
            if (!kv.second.h.shelved) continue;
            if (kv.first.find('\t') != std::string::npos || kv.first.find('\n') != std::string::npos) continue;   // cannot be recorded; stays in memory only
            std::string name = kv.second.pending.substr(kv.second.pending.find_last_of('/') + 1);
            out << name << '\t' << kv.second.h.owner_pid << '\t' << kv.second.h.owner_ppid << '\t' << kv.first << '\n';
            ++cnt;
        }
    }
    if (cnt == 0) { unlink(tmp.c_str()); unlink(fin.c_str()); return; }
    rename(tmp.c_str(), fin.c_str());
}

bool HoldBack::is_held(const std::string& rel) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = held_.find(rel);
    return it != held_.end() && !it->second.h.shelved;
}

static std::atomic<bool> g_fast_copy{false};
void HoldBack::set_fast_copy(bool on) { g_fast_copy = on; }
bool HoldBack::fast_copy() { return g_fast_copy; }

bool HoldBack::copy_file_preserving(const std::string& src, const std::string& dst) {
    int in = open(src.c_str(), O_RDONLY);
    if (in < 0) return false;
    struct stat st{};
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) { close(in); return false; }
    int out = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (out < 0) { close(in); return false; }
    std::vector<char> buf(1 << 20);
    bool ok = true;
    bool done = false;
    if (g_fast_copy) {
        if (ioctl(out, FICLONE, in) == 0) done = true;            // reflink: shares extents, no data copy (btrfs, xfs, ...)
        else {
            off_t left = st.st_size; bool fail = false;
            while (left > 0) {
                ssize_t c = copy_file_range(in, nullptr, out, nullptr, static_cast<size_t>(left), 0);   // in-kernel copy
                if (c <= 0) { fail = true; break; }
                left -= c;
            }
            if (!fail) done = true;
            else { lseek(in, 0, SEEK_SET); lseek(out, 0, SEEK_SET); if (ftruncate(out, 0) != 0) ok = false; }
        }
    }
    while (ok && !done) {
        ssize_t r = read(in, buf.data(), buf.size());
        if (r < 0) { ok = false; break; }
        if (r == 0) break;
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf.data() + off, static_cast<size_t>(r - off));
            if (w < 0) { ok = false; break; }
            off += w;
        }
        if (!ok) break;
    }
    fchmod(out, st.st_mode & 07777);
    struct timespec ts[2] = {st.st_atim, st.st_mtim};
    futimens(out, ts);
    close(in); close(out);
    if (!ok) unlink(dst.c_str());
    return ok;
}

bool HoldBack::hold(const std::string& rel, long owner_pid, long owner_ppid, size_t max_bytes) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto ex = held_.find(rel);
    if (ex != held_.end()) {
        if (!ex->second.h.shelved) return true;
        unlink(ex->second.pending.c_str()); held_.erase(ex);   // a new writer supersedes a shelved copy
        persist_shelf_locked();
    }
    std::string src = backing_ + "/" + rel;
    struct stat st{};
    if (lstat(src.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    if (static_cast<size_t>(st.st_size) > max_bytes) return false;
    std::string pend = pending_root_ + "/p" + std::to_string(next_id_++);
    if (!copy_file_preserving(src, pend)) return false;
    Entry e;
    e.h.rel = rel; e.h.owner_pid = owner_pid; e.h.owner_ppid = owner_ppid;
    e.h.last_write_ms = e.h.held_since_ms = now_ms();
    e.pending = pend;
    held_[rel] = std::move(e);
    return true;
}

void HoldBack::touch(const std::string& rel, long, long) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = held_.find(rel);
    if (it != held_.end()) it->second.h.last_write_ms = now_ms();
}

bool HoldBack::rekey(const std::string& from, const std::string& to) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = held_.find(from);
    if (it == held_.end()) return false;
    auto old_to = held_.find(to);
    if (old_to != held_.end()) { unlink(old_to->second.pending.c_str()); held_.erase(old_to); }
    Entry e = std::move(it->second);
    held_.erase(from);
    e.h.rel = to;
    held_[to] = std::move(e);
    return true;
}

void HoldBack::drop(const std::string& rel) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = held_.find(rel);
    if (it == held_.end()) return;
    bool was = it->second.h.shelved;
    unlink(it->second.pending.c_str());
    held_.erase(it);
    if (was) persist_shelf_locked();
}

bool HoldBack::commit_locked(std::map<std::string, Entry>::iterator it) {
    std::string dst = backing_ + "/" + it->second.h.rel;
    bool ok = rename(it->second.pending.c_str(), dst.c_str()) == 0;
    if (!ok) unlink(it->second.pending.c_str());   // target vanished; nothing sensible to commit to
    held_.erase(it);
    return ok;
}

bool HoldBack::commit(const std::string& rel) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = held_.find(rel);
    return it != held_.end() && commit_locked(it);
}

bool HoldBack::commit_if(const std::string& rel, const std::function<bool(long, long)>& ok) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = held_.find(rel);
    return it != held_.end() && ok(it->second.h.owner_pid, it->second.h.owner_ppid) && commit_locked(it);
}

size_t HoldBack::shelve_owner(long key) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    size_t n = 0;
    for (auto& kv : held_)
        if (!kv.second.h.shelved && (kv.second.h.owner_pid == key || kv.second.h.owner_ppid == key)) { kv.second.h.shelved = true; ++n; }
    if (n) persist_shelf_locked();
    return n;
}

std::vector<std::string> HoldBack::release_owner(long key) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::vector<std::string> out;
    for (auto it = held_.begin(); it != held_.end();) {
        if (it->second.h.shelved && (it->second.h.owner_pid == key || it->second.h.owner_ppid == key)) {
            auto cur = it++; std::string r = cur->first;
            if (commit_locked(cur)) out.push_back(r);
        } else ++it;
    }
    persist_shelf_locked();
    return out;
}

std::vector<std::string> HoldBack::revert_owner(long key) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::vector<std::string> out;
    for (auto it = held_.begin(); it != held_.end();) {
        if (it->second.h.owner_pid == key || it->second.h.owner_ppid == key) {
            unlink(it->second.pending.c_str());
            out.push_back(it->first);
            it = held_.erase(it);
        } else ++it;
    }
    persist_shelf_locked();
    return out;
}

size_t HoldBack::commit_due(long long delay_ms, const std::function<bool(long, long)>& ok) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    long long now = now_ms();
    size_t n = 0;
    for (auto it = held_.begin(); it != held_.end();) {
        if (!it->second.h.shelved && now - it->second.h.last_write_ms >= delay_ms &&
            ok(it->second.h.owner_pid, it->second.h.owner_ppid)) {
            auto cur = it++;
            if (commit_locked(cur)) ++n;
        } else ++it;
    }
    return n;
}

size_t HoldBack::enforce_limit(size_t max_files) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    size_t n = 0;
    while (held_.size() > max_files) {
        auto oldest = held_.end();
        for (auto it = held_.begin(); it != held_.end(); ++it)
            if (!it->second.h.shelved && (oldest == held_.end() || it->second.h.held_since_ms < oldest->second.h.held_since_ms)) oldest = it;
        if (oldest == held_.end()) break;
        if (commit_locked(oldest)) ++n;
    }
    return n;
}

size_t HoldBack::commit_all() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    size_t n = 0;
    persist_shelf_locked();      // shelved copies stay on disk (and in the manifest) across a clean unmount
    while (!held_.empty()) {
        auto it = held_.begin();
        if (it->second.h.shelved) { held_.erase(it); continue; }   // file + manifest line are kept for a later release/discard
        if (commit_locked(it)) ++n;
    }
    return n;
}

size_t HoldBack::count() {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return held_.size();
}

std::vector<HoldBack::Held> HoldBack::list() {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<Held> v;
    for (auto& kv : held_) v.push_back(kv.second.h);
    return v;
}
