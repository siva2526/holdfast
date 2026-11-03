// tests/test_promote_rate_limit.cpp -- regression test for an audited
// control-channel abuse: 15 anonymous PROMOTE commands created 15
// full-tree checkpoint copies back-to-back with no cooldown. This
// asserts the rate limiter rejects a rapid-fire second call and
// recovers once the interval has elapsed, and that the default
// (unset) behavior remains unlimited so other tests are unaffected.
#include "canary_manager.hpp"
#include <cassert>
#include <fstream>
#include <iostream>
#include <thread>
#include <unistd.h>

namespace {
std::string make_tmp_root() {
    char tmpl[] = "/tmp/rrfs_ratelimit_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) throw std::runtime_error("mkdtemp failed");
    return std::string(dir);
}
} // namespace

int main() {
    std::string root = make_tmp_root();
    CanaryManager cm(root + "/backing", root + "/canary", root + "/checkpoints", 8);
    cm.init();
    std::ofstream(root + "/backing/x.txt") << "x";

    // Default: unlimited, so two rapid promotions both succeed.
    {
        auto id1 = cm.promote_checkpoint("manual");
        auto id2 = cm.promote_checkpoint("manual");
        assert(!id1.empty() && !id2.empty() && id1 != id2);
    }

    // With a limit set, a rapid-fire second call is rejected (empty id).
    {
        CanaryManager cm2(root + "/backing2", root + "/canary2", root + "/checkpoints2", 8);
        std::ofstream(root + "/backing2").close(); // ensure parent exists via init()
        cm2.init();
        std::ofstream(root + "/backing2/y.txt") << "y";
        cm2.set_min_promote_interval_ms(300);

        auto first = cm2.promote_checkpoint("manual");
        assert(!first.empty());
        auto second = cm2.promote_checkpoint("manual"); // immediately after
        assert(second.empty());                          // rejected

        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        auto third = cm2.promote_checkpoint("manual");    // after the cooldown
        assert(!third.empty());
    }

    std::cout << "test_promote_rate_limit: ALL PASSED\n";
    return 0;
}
