// tests/test_canary_manager.cpp -- end-to-end test of the canary
// snapshot / atomic rollback path, without needing a FUSE mount:
// exercises CanaryManager directly against a temp directory tree.
#include "canary_manager.hpp"

#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace {

std::string slurp(const std::string& p) {
    std::ifstream in(p);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void write_file(const std::string& p, const std::string& content) {
    std::ofstream out(p);
    out << content;
}

std::string make_tmp_root() {
    char tmpl[] = "/tmp/rrfs_test_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) throw std::runtime_error("mkdtemp failed");
    return std::string(dir);
}

} // namespace

int main() {
    std::string root = make_tmp_root();
    std::string backing = root + "/backing";
    std::string canary = root + "/canary";
    std::string checkpoints = root + "/checkpoints";

    CanaryManager cm(backing, canary, checkpoints, /*ring_size=*/4);
    cm.init();

    write_file(backing + "/doc1.txt", "original content 1");
    write_file(backing + "/doc2.txt", "original content 2");

    // 1. Baseline checkpoint captures current (clean) state.
    std::string baseline = cm.promote_checkpoint("manual", -1, -1);
    assert(!baseline.empty());

    // 2. Simulate an attacker process: protect-before-write (as the
    //    FUSE write handler does), then overwrite with "ciphertext".
    cm.protect_before_write("doc1.txt");
    write_file(backing + "/doc1.txt", "ENCRYPTED GARBAGE");
    cm.protect_before_write("doc2.txt");
    write_file(backing + "/doc2.txt", "ENCRYPTED GARBAGE 2");
    assert(slurp(backing + "/doc1.txt") == "ENCRYPTED GARBAGE");

    // 3. Detection fires: an auto checkpoint is promoted with the
    //    triggering pid/score recorded.
    std::string auto_ckpt = cm.promote_checkpoint("auto", /*pid=*/4242, /*score=*/15.5);
    assert(!auto_ckpt.empty());
    assert(auto_ckpt != baseline);

    // 4. Checkpoint listing round-trips metadata correctly.
    auto list = cm.list_checkpoints();
    assert(list.size() == 2);
    bool found_auto = false;
    for (auto& c : list) {
        if (c.id == auto_ckpt) {
            found_auto = true;
            assert(c.reason == "auto");
            assert(c.trigger_pid == 4242);
            assert(c.trigger_score > 15.0 && c.trigger_score < 16.0);
        }
    }
    assert(found_auto);

    // 5. Atomic rollback to the pre-attack baseline restores content.
    bool ok = cm.rollback(baseline);
    assert(ok);
    assert(slurp(backing + "/doc1.txt") == "original content 1");
    assert(slurp(backing + "/doc2.txt") == "original content 2");

    // 6. Rollback to an unknown checkpoint id fails cleanly (no
    //    partial/corrupted state).
    assert(cm.rollback("does_not_exist") == false);
    assert(slurp(backing + "/doc1.txt") == "original content 1"); // unchanged

    std::cout << "test_canary_manager: ALL PASSED\n";
    return 0;
}
