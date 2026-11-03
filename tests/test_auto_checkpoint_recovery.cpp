// tests/test_auto_checkpoint_recovery.cpp -- regression test for the
// central B2 fix found by an independent audit: an "auto" checkpoint
// used to be a plain copy of the live tree AT DETECTION TIME, which
// already contained whatever damage had landed by then, even though
// protect_before_write() had already preserved the pre-damage bytes
// in a canary generation. This test proves promote_checkpoint("auto")
// now reconstructs pre-attack content from those canary copies,
// including restoring a file under its ORIGINAL name after the
// attacker has renamed the live copy away (the "rename-over" gap).
#include "canary_manager.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h>

namespace {
std::string make_tmp_root() {
    char tmpl[] = "/tmp/rrfs_autockpt_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) throw std::runtime_error("mkdtemp failed");
    return std::string(dir);
}
void write_file(const std::string& p, const std::string& content) {
    std::ofstream out(p);
    out << content;
}
std::string slurp(const std::string& p) {
    std::ifstream in(p);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
} // namespace

int main() {
    std::string root = make_tmp_root();
    std::string backing = root + "/backing";
    std::string canary = root + "/canary";
    std::string checkpoints = root + "/checkpoints";

    CanaryManager cm(backing, canary, checkpoints, /*ring_size=*/8);
    cm.init();

    // Seed three original files.
    write_file(backing + "/a.txt", "ORIGINAL A");
    write_file(backing + "/b.txt", "ORIGINAL B");
    write_file(backing + "/c.txt", "ORIGINAL C (never touched by the attack)");

    // Simulate the FUSE write path: protect, THEN damage.
    // a.txt: overwritten in place.
    cm.protect_before_write("a.txt");
    write_file(backing + "/a.txt", "CIPHERTEXT-A");

    // b.txt: "write ciphertext to a new file, then rename over the
    // original" -- the FUSE layer must protect the RENAME TARGET
    // (b.txt) before the rename, not just the source.
    write_file(backing + "/b_new", "CIPHERTEXT-B");
    cm.protect_before_write("b.txt");   // <-- the fix: protect the target
    rename((backing + "/b_new").c_str(), (backing + "/b.txt").c_str());

    // c.txt is left alone entirely.

    // Detection fires here: auto checkpoint is promoted.
    std::string auto_id = cm.promote_checkpoint("auto", /*pid=*/999, /*score=*/42.0);
    assert(!auto_id.empty());

    // The auto checkpoint must hold PRE-ATTACK content for a.txt and
    // b.txt (reconstructed from canary), and the untouched content for
    // c.txt (from live, since it was never damaged).
    std::string ckpt_dir = checkpoints + "/" + auto_id;
    assert(slurp(ckpt_dir + "/a.txt") == "ORIGINAL A");
    assert(slurp(ckpt_dir + "/b.txt") == "ORIGINAL B");
    assert(slurp(ckpt_dir + "/c.txt") == "ORIGINAL C (never touched by the attack)");

    // And rolling back to it must restore the live tree to that state.
    bool ok = cm.rollback(auto_id);
    assert(ok);
    assert(slurp(backing + "/a.txt") == "ORIGINAL A");
    assert(slurp(backing + "/b.txt") == "ORIGINAL B");
    assert(slurp(backing + "/c.txt") == "ORIGINAL C (never touched by the attack)");

    std::cout << "test_auto_checkpoint_recovery: ALL PASSED\n";
    return 0;
}
