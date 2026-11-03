#pragma once
// Hold-back overlay ("write quarantine") for destructive writes.
//
// The first time a process overwrites or truncates an EXISTING file, the
// file is copied to a pending area and the write is applied to that
// pending copy. The backing store keeps the original bytes untouched.
// Every reader sees the pending content (the view is transparent), but
// nothing destructive reaches the backing store until the write is
// committed -- after `commit_delay_ms` of quiet and only while the owning
// process looks innocent. If the owner is flagged first, its pending
// copies are simply discarded: the attack never landed on the store and
// zero files are lost. Whole-file granularity; files above a size limit
// are not held (they fall back to in-place write + copy-on-write).
#include <cstddef>
#include <functional>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

class HoldBack {
public:
    struct Held {
        std::string rel;
        long owner_pid = -1;
        long owner_ppid = -1;
        long long last_write_ms = 0;
        long long held_since_ms = 0;
        bool shelved = false;     // owner was flagged: invisible to readers, never auto-committed; operator may release or discard
    };

    HoldBack(std::string backing_root, std::string pending_root);

    // Creates the pending directory. Shelved copies listed in shelf.manifest are recovered (hidden, releasable by their
    // old pid); every other leftover pending file is DISCARDED, because the backing store still holds the previous version
    // (the conservative state; an edit acknowledged just before a crash is lost). Returns how many files were discarded.
    size_t init();

    // RAII shared access to a path's effective location (pending copy if
    // held, otherwise the backing file). Holds a shared lock so a
    // concurrent commit/drop cannot pull the file away mid-operation.
    class Access {
    public:
        Access(HoldBack& hb, const std::string& rel);
        const std::string& path() const { return path_; }
        bool held() const { return held_; }
    private:
        std::shared_lock<std::shared_mutex> lk_;
        std::string path_;
        bool held_ = false;
    };

    bool is_held(const std::string& rel);

    // Ensure `rel` is held (copy to pending if needed). False if the file
    // does not exist, is not a regular file, exceeds max_bytes, or the
    // copy failed -- the caller then falls back to an in-place write.
    bool hold(const std::string& rel, long owner_pid, long owner_ppid, size_t max_bytes);

    void touch(const std::string& rel, long writer_pid, long writer_ppid);
    bool rekey(const std::string& from, const std::string& to);   // held file renamed
    void drop(const std::string& rel);                            // file deleted / replaced
    bool commit(const std::string& rel);                          // pending replaces backing
    // Commit `rel` now (fsync) if ok(owner_pid, owner_ppid) holds. Returns true if committed.
    bool commit_if(const std::string& rel, const std::function<bool(long, long)>& ok);

    // "shelving": on a hard detection the owner's pending copies are hidden from readers (they see the
    // original) and never auto-committed, but are KEPT so that a false positive costs a delay, not lost work.
    size_t shelve_owner(long key);
    // shelved copies survive a daemon restart (see persist_shelf_locked / init). Returns how many were recovered.
    size_t recovered_shelved() const { return recovered_; }
    std::vector<std::string> release_owner(long key);   // commit shelved copies of `key` (operator override)

    // Discard every pending copy whose owner pid or parent matches `key`.
    std::vector<std::string> revert_owner(long key);

    // Commit entries quiet for >= delay_ms for which ok(owner_pid, owner_ppid) holds.
    size_t commit_due(long long delay_ms, const std::function<bool(long, long)>& ok);
    // Force-commit the oldest entries until at most `max_files` remain.
    size_t enforce_limit(size_t max_files);
    size_t commit_all();

    size_t count();
    std::vector<Held> list();

    static long long now_ms();

    // Opt-in: make pending copies with FICLONE (reflink) or copy_file_range before falling back to read/write.
    static void set_fast_copy(bool on);
    static bool fast_copy();
private:
    struct Entry { Held h; std::string pending; };
    bool commit_locked(std::map<std::string, Entry>::iterator it);
    static bool copy_file_preserving(const std::string& src, const std::string& dst);

    std::string backing_;
    std::string pending_root_;
    size_t recovered_ = 0;
    void persist_shelf_locked();
    std::shared_mutex mu_;
    std::map<std::string, Entry> held_;
    unsigned long long next_id_ = 1;
};
