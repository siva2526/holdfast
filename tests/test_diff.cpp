// tests/test_diff.cpp -- unit tests for CanaryManager::diff_against().
//
// Case 1 specifically pins down a real bug found while building this
// feature: the checkpoint's own meta.json bookkeeping file was being
// swept into the file comparison and reported as a false "removed"
// entry on every single diff, since the live tree never has a
// meta.json of its own. Fixed by excluding it explicitly in
// diff_against(); this test exists so that fix can't silently regress.
#include "canary_manager.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <unistd.h>

namespace {

std::string make_tmp_root() {
    char tmpl[] = "/tmp/rrfs_difftest_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) throw std::runtime_error("mkdtemp failed");
    return std::string(dir);
}

void write_file(const std::string& p, const std::string& content) {
    std::ofstream out(p);
    out << content;
}

} // namespace

int main() {
    std::string root = make_tmp_root();
    std::string backing = root + "/backing";
    std::string canary = root + "/canary";
    std::string checkpoints = root + "/checkpoints";

    CanaryManager cm(backing, canary, checkpoints, /*ring_size=*/4);
    cm.init();

    write_file(backing + "/a.txt", "hello a");
    write_file(backing + "/b.txt", "hello b");
    write_file(backing + "/c.txt", "hello c");
    std::string ckpt = cm.promote_checkpoint("manual");

    // Case 1: no changes since the checkpoint -> all 3 files unchanged,
    // and critically, meta.json must NOT appear as "removed".
    {
        auto d = cm.diff_against(ckpt);
        assert(d.unchanged.size() == 3);
        assert(d.modified.empty());
        assert(d.added.empty());
        assert(d.removed.empty());
    }

    // Case 2: modify one file, delete another, add a new one.
    write_file(backing + "/a.txt", "MODIFIED CONTENT");
    unlink((backing + "/b.txt").c_str());
    write_file(backing + "/d.txt", "brand new file");
    {
        auto d = cm.diff_against(ckpt);
        assert(d.modified.size() == 1 && d.modified[0] == "a.txt");
        assert(d.removed.size() == 1 && d.removed[0] == "b.txt");
        assert(d.added.size() == 1 && d.added[0] == "d.txt");
        assert(d.unchanged.size() == 1 && d.unchanged[0] == "c.txt");

        std::string report = CanaryManager::format_diff(d);
        assert(report.find("a.txt") != std::string::npos);
        assert(report.find("meta.json") == std::string::npos); // never leaks into output
    }

    // Case 3: unknown checkpoint id -> empty result, not a crash.
    {
        auto d = cm.diff_against("no_such_checkpoint");
        assert(d.added.empty() && d.removed.empty() && d.modified.empty() && d.unchanged.empty());
    }

    // Case 4: diff_against is read-only -- rollback afterward still
    // works and restores the true original state.
    {
        bool ok = cm.rollback(ckpt);
        assert(ok);
        std::ifstream in(backing + "/a.txt");
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        assert(content == "hello a");
    }

    std::cout << "test_diff: ALL PASSED\n";
    return 0;
}
