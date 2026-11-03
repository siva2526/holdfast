// tests/test_auto_checkpoint_rename_chain.cpp -- regression test for a
// bug found while verifying the B2 fix live: the first version of
// auto-checkpoint reconstruction restored a renamed file's ORIGINAL
// name correctly, but also left the DAMAGED file under its NEW name
// in the same checkpoint -- a duplicate rather than a true undo.
// Confirmed live: after a real attack (doc.txt -> doc.txt.locked),
// the automatic checkpoint still contained .locked files. Fixed via
// CanaryManager::record_rename(), which lets reconstruction drop the
// rename destination before overlaying the canary-preserved original.
#include "canary_manager.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h>

namespace {
std::string make_tmp_root() {
    char tmpl[] = "/tmp/rrfs_renamechain_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) throw std::runtime_error("mkdtemp failed");
    return std::string(dir);
}
void write_file(const std::string& p, const std::string& content) {
    std::ofstream out(p);
    out << content;
}
bool exists(const std::string& p) {
    std::ifstream in(p);
    return static_cast<bool>(in);
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
    CanaryManager cm(backing, root + "/canary", root + "/checkpoints", 8);
    cm.init();

    // Classic ransomware pattern: overwrite doc.txt, then rename it to
    // a DIFFERENT name (doc.txt.locked). This is exactly what the
    // FUSE daemon does in handle_pre_rename: protect both endpoints,
    // record the rename, then the OS rename proceeds.
    write_file(backing + "/doc.txt", "ORIGINAL DOCUMENT");
    cm.protect_before_write("doc.txt");
    write_file(backing + "/doc.txt", "CIPHERTEXT");
    cm.protect_before_write("doc.txt");       // already protected this generation: no-op
    cm.protect_before_write("doc.txt.locked"); // destination didn't exist: no-op
    cm.record_rename("doc.txt", "doc.txt.locked");
    rename((backing + "/doc.txt").c_str(), (backing + "/doc.txt.locked").c_str());

    std::string auto_id = cm.promote_checkpoint("auto", 123, 99.0);
    assert(!auto_id.empty());
    std::string ckpt_dir = root + "/checkpoints/" + auto_id;

    // The checkpoint must contain the restored ORIGINAL under its
    // original name, and must NOT also contain a damaged copy under
    // the new name (that was the bug: both existed at once).
    assert(exists(ckpt_dir + "/doc.txt"));
    assert(slurp(ckpt_dir + "/doc.txt") == "ORIGINAL DOCUMENT");
    assert(!exists(ckpt_dir + "/doc.txt.locked"));

    // A three-hop chain (a -> b -> c) must unwind to just "a".
    write_file(backing + "/a.txt", "CHAIN ORIGINAL");
    cm.protect_before_write("a.txt");
    cm.record_rename("a.txt", "b.txt");
    rename((backing + "/a.txt").c_str(), (backing + "/b.txt").c_str());
    cm.protect_before_write("b.txt"); // already-renamed content; captured under "b.txt" too
    cm.record_rename("b.txt", "c.txt");
    rename((backing + "/b.txt").c_str(), (backing + "/c.txt").c_str());

    std::string auto_id2 = cm.promote_checkpoint("auto", 124, 99.0);
    std::string ckpt_dir2 = root + "/checkpoints/" + auto_id2;
    assert(exists(ckpt_dir2 + "/a.txt"));
    assert(slurp(ckpt_dir2 + "/a.txt") == "CHAIN ORIGINAL");
    assert(!exists(ckpt_dir2 + "/b.txt"));
    assert(!exists(ckpt_dir2 + "/c.txt"));

    // Rename-OVER (audit finding: recovered 0/10 live): the attacker writes
    // ciphertext to a temp file and renames it over a PRE-EXISTING
    // victim. The victim's original bytes must survive in the auto
    // checkpoint under the victim's own name.
    write_file(backing + "/victim.txt", "VICTIM ORIGINAL");
    cm.protect_before_write("tmp.enc");      // from: attacker's temp (created fresh)
    write_file(backing + "/tmp.enc", "RANDOM-CIPHERTEXT");
    cm.protect_before_write("tmp.enc");
    cm.protect_before_write("victim.txt");   // to: pre-existing, canary keeps original
    cm.record_rename("tmp.enc", "victim.txt", /*dest_preexisted=*/true);
    rename((backing + "/tmp.enc").c_str(), (backing + "/victim.txt").c_str());
    std::string auto_id3 = cm.promote_checkpoint("auto", 125, 99.0);
    std::string ckpt_dir3 = root + "/checkpoints/" + auto_id3;
    assert(exists(ckpt_dir3 + "/victim.txt"));
    assert(slurp(ckpt_dir3 + "/victim.txt") == "VICTIM ORIGINAL");

    std::cout << "test_auto_checkpoint_rename_chain: ALL PASSED\n";
    return 0;
}
