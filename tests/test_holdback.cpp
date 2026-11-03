// tests/test_holdback.cpp -- hold-back overlay and scoped repair.
#include "canary_manager.hpp"
#include "holdback.hpp"
#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

static std::string slurp(const std::string& p) { std::ifstream i(p); std::ostringstream s; s << i.rdbuf(); return s.str(); }
static void put(const std::string& p, const std::string& c) { std::ofstream(p) << c; }

int main() {
    char t[] = "/tmp/rrfs_hold_XXXXXX"; std::string root = mkdtemp(t);
    std::string b = root + "/backing"; mkdir(b.c_str(), 0755);
    HoldBack hb(b, root + "/pending"); hb.init();
    put(b + "/a.txt", "ORIGINAL-A"); put(b + "/b.txt", "ORIGINAL-B"); put(b + "/c.txt", "ORIGINAL-C");

    // hold: writes go to pending, backing stays original, readers see pending.
    assert(hb.hold("a.txt", 100, 10, 1 << 20));
    { HoldBack::Access a(hb, "a.txt"); assert(a.held()); put(a.path(), "CIPHERTEXT"); }
    assert(slurp(b + "/a.txt") == "ORIGINAL-A");
    { HoldBack::Access a(hb, "a.txt"); assert(slurp(a.path()) == "CIPHERTEXT"); }
    assert(!hb.hold("missing.txt", 1, 1, 1 << 20));       // nonexistent => not holdable
    assert(!hb.hold("a.txt", 100, 10, 1) == false);        // already held => true

    // size limit
    assert(!hb.hold("b.txt", 100, 10, 3));

    // revert by owner pid: pending dropped, backing never changed.
    assert(hb.hold("b.txt", 100, 10, 1 << 20));
    { HoldBack::Access a(hb, "b.txt"); put(a.path(), "XXXX"); }
    auto rv = hb.revert_owner(100);
    assert(rv.size() == 2 && hb.count() == 0);
    assert(slurp(b + "/a.txt") == "ORIGINAL-A" && slurp(b + "/b.txt") == "ORIGINAL-B");

    // revert by parent bucket (process-tree aggregation) and non-matching owner untouched.
    assert(hb.hold("a.txt", 200, 77, 1 << 20)); assert(hb.hold("b.txt", 201, 77, 1 << 20)); assert(hb.hold("c.txt", 300, 5, 1 << 20));
    assert(hb.revert_owner(77).size() == 2 && hb.is_held("c.txt") && !hb.is_held("a.txt"));
    hb.drop("c.txt");

    // commit: pending atomically replaces backing; commit_due honours delay and the ok() predicate.
    assert(hb.hold("a.txt", 1, 1, 1 << 20));
    { HoldBack::Access a(hb, "a.txt"); put(a.path(), "EDITED-BY-USER"); }
    assert(hb.commit_due(100000, [](long, long) { return true; }) == 0);   // not quiet long enough
    assert(hb.commit_due(0, [](long, long) { return false; }) == 0);      // owner not trusted
    assert(slurp(b + "/a.txt") == "ORIGINAL-A");
    assert(hb.commit_due(0, [](long, long) { return true; }) == 1);
    assert(slurp(b + "/a.txt") == "EDITED-BY-USER" && hb.count() == 0);

    // rekey follows a rename of a held file; commit lands on the new name.
    assert(hb.hold("b.txt", 1, 1, 1 << 20)); { HoldBack::Access a(hb, "b.txt"); put(a.path(), "NEW-B"); }
    rename((b + "/b.txt").c_str(), (b + "/b2.txt").c_str());
    assert(hb.rekey("b.txt", "b2.txt") && hb.is_held("b2.txt") && !hb.is_held("b.txt"));
    assert(hb.commit("b2.txt") && slurp(b + "/b2.txt") == "NEW-B");

    // leftover pending files are discarded on init (conservative recovery).
    put(root + "/pending/p999", "stale");
    HoldBack hb2(b, root + "/pending"); assert(hb2.init() == 1);

    // ---- scoped repair via canary: restore overwritten, quarantine created, never delete.
    CanaryManager cm(b, root + "/canary", root + "/checkpoints", 8); cm.init();
    put(b + "/v.txt", "VICTIM-ORIGINAL");
    cm.protect_before_write("v.txt");
    put(b + "/v.txt", "RANDOM");                       // attacker overwrote in place
    put(b + "/tmp.enc", "NEW-CIPHERTEXT");             // attacker-created file
    std::string q = root + "/quarantine";
    assert(cm.repair_path("v.txt", true, q) == 1 && slurp(b + "/v.txt") == "VICTIM-ORIGINAL");
    assert(slurp(q + "/v.txt") == "RANDOM");           // attacker's bytes preserved, not destroyed
    assert(cm.repair_path("tmp.enc", false, q) == 2);
    struct stat st; assert(stat((b + "/tmp.enc").c_str(), &st) != 0 && stat((q + "/tmp.enc").c_str(), &st) == 0);
    assert(cm.repair_path("v.txt", true, q) == 0);     // already identical => no-op
    assert(cm.repair_path("never_protected.txt", true, q) == 0);
    std::cout << "test_holdback: ALL PASSED\n";
    // shelving: hidden from readers, never auto-committed, releasable, discardable, superseded by a new writer.
    {
        put(b + "/s.txt", "ORIG-S");
        assert(hb.hold("s.txt", 900, 9, 1 << 20));
        { HoldBack::Access a(hb, "s.txt"); put(a.path(), "EVIL"); }
        assert(hb.shelve_owner(900) == 1);
        { HoldBack::Access a(hb, "s.txt"); assert(!a.held() && slurp(a.path()) == "ORIG-S"); }
        assert(!hb.is_held("s.txt"));
        assert(hb.commit_due(0, [](long, long) { return true; }) == 0 && slurp(b + "/s.txt") == "ORIG-S");
        auto rel = hb.release_owner(900);
        assert(rel.size() == 1 && slurp(b + "/s.txt") == "EVIL" && hb.count() == 0);
        put(b + "/s2.txt", "ORIG-2");
        assert(hb.hold("s2.txt", 901, 9, 1 << 20)); hb.shelve_owner(901);
        assert(hb.revert_owner(901).size() == 1 && slurp(b + "/s2.txt") == "ORIG-2" && hb.count() == 0);
    }

    // shelved writes survive a daemon restart (manifest), unshelved leftovers are dropped.
    {
        put(b + "/r1.txt", "ORIG-R1"); put(b + "/r2.txt", "ORIG-R2");
        assert(hb.hold("r1.txt", 950, 9, 1 << 20)); assert(hb.hold("r2.txt", 951, 9, 1 << 20));
        { HoldBack::Access a(hb, "r1.txt"); put(a.path(), "EVIL-R1"); }
        { HoldBack::Access a(hb, "r2.txt"); put(a.path(), "UNSHELVED"); }
        assert(hb.shelve_owner(950) == 1);
        // (daemon crash: no commit_all) -- the manifest was written when the copy was shelved
        HoldBack hb2(b, root + "/pending"); hb2.init();    // "restart"
        assert(hb2.recovered_shelved() == 1 && hb2.count() == 1);
        { HoldBack::Access a(hb2, "r1.txt"); assert(!a.held() && slurp(a.path()) == "ORIG-R1"); }   // still hidden from readers
        assert(slurp(b + "/r2.txt") == "ORIG-R2");         // the unshelved write was dropped; original untouched
        assert(hb2.release_owner(950).size() == 1 && slurp(b + "/r1.txt") == "EVIL-R1");
        HoldBack hb3(b, root + "/pending"); hb3.init();
        assert(hb3.recovered_shelved() == 0);              // nothing left to recover after release
    }
    // unrepair_path puts a quarantined file back and keeps what repair restored.
    {
        put(b + "/u.txt", "U-ORIGINAL");
        cm.protect_before_write("u.txt");
        put(b + "/u.txt", "U-NEW-BY-PROCESS");
        std::string q2 = root + "/quarantine2", undo = root + "/undo";
        assert(cm.repair_path("u.txt", true, q2) == 1 && slurp(b + "/u.txt") == "U-ORIGINAL");
        assert(cm.unrepair_path("u.txt", q2, undo) && slurp(b + "/u.txt") == "U-NEW-BY-PROCESS" && slurp(undo + "/u.txt") == "U-ORIGINAL");
        assert(!cm.unrepair_path("u.txt", q2, undo));      // nothing left to undo
    }

    return 0;
}
