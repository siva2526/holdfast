#pragma once
#include <mutex>
#include <string>
#include <unordered_map>

// Tracks per-path file extensions to detect the "rename to a random/
// suspicious extension" pattern common to cryptographic ransomware
// (e.g. doc.txt -> doc.txt.locked).
//
// Split out as its own class (rather than living inline in
// rrfs_fuse.cpp) specifically so it's unit-testable without a FUSE
// mount -- this is exactly the kind of signal that's easy to get
// subtly wrong (see tests/test_ext_tracker.cpp for the bug this
// caught: checking the wrong path's extension history on rename).
class ExtensionTracker {
public:
    // Same-path check: has `path`'s extension changed since the last
    // time we recorded it? Used for ordinary writes/truncates, where
    // the path identity doesn't change mid-call.
    bool on_write(const std::string& path);

    // Rename-specific check: does `to`'s extension differ from
    // `from`'s? This is the actual "renamed to a different extension"
    // signature -- checking `from`'s own extension history (as
    // on_write() would) never sees it, because the from-path's
    // extension never changes; only the identity does.
    bool on_rename(const std::string& from, const std::string& to);

private:
    static bool extension_of(const std::string& path, std::string* ext);

    std::mutex mu_;
    std::unordered_map<std::string, std::string> last_ext_;
};
