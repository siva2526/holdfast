// tests/test_checkpoint_retention.cpp -- scheduled checkpoints are pruned
// oldest-first beyond the cap; manual and auto checkpoints are never pruned.
#include "canary_manager.hpp"
#include <cassert>
#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>
#include <unistd.h>

int main() {
    char tmpl[] = "/tmp/rrfs_retention_XXXXXX";
    std::string root = mkdtemp(tmpl);
    CanaryManager cm(root + "/backing", root + "/canary", root + "/checkpoints", 8);
    cm.init();
    std::ofstream(root + "/backing/x.txt") << "x";
    cm.set_max_scheduled_checkpoints(2);

    auto pause = [] { std::this_thread::sleep_for(std::chrono::milliseconds(5)); };
    std::string manual = cm.promote_checkpoint("manual"); pause();
    std::string s1 = cm.promote_checkpoint("scheduled"); pause();
    std::string autoc = cm.promote_checkpoint("auto", 42, 11.0); pause();
    std::string s2 = cm.promote_checkpoint("scheduled"); pause();
    std::string s3 = cm.promote_checkpoint("scheduled"); pause();
    std::string s4 = cm.promote_checkpoint("scheduled");

    auto list = cm.list_checkpoints();
    auto has = [&](const std::string& id) {
        for (auto& c : list) if (c.id == id) return true;
        return false;
    };
    assert(has(manual) && has(autoc));            // never pruned
    assert(!has(s1) && !has(s2));                 // oldest scheduled pruned
    assert(has(s3) && has(s4));                   // newest 2 kept
    assert(list.size() == 4);
    std::cout << "test_checkpoint_retention OK\n";
    return 0;
}
