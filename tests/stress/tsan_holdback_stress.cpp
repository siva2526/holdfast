// ThreadSanitizer stress for HoldBack + CanaryManager::repair_path under concurrent use.
// g++ -std=c++17 -fsanitize=thread -O1 -Iinclude tests/stress/tsan_holdback_stress.cpp src/holdback.cpp src/canary_manager.cpp -lpthread
#include "canary_manager.hpp"
#include "holdback.hpp"
#include <atomic>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
int main() {
    char t[] = "/tmp/rrfs_tsan_XXXXXX"; std::string root = mkdtemp(t), b = root + "/backing";
    mkdir(b.c_str(), 0755);
    for (int i = 0; i < 16; ++i) std::ofstream(b + "/f" + std::to_string(i)) << "orig" << i;
    HoldBack hb(b, root + "/pending"); hb.init();
    CanaryManager cm(b, root + "/canary", root + "/checkpoints", 8); cm.init();
    std::atomic<bool> stop{false};
    std::vector<std::thread> th;
    for (int w = 0; w < 4; ++w) th.emplace_back([&, w] {
        unsigned x = w + 1;
        while (!stop) {
            x = x * 1103515245u + 12345u; std::string rel = "f" + std::to_string((x >> 8) % 16);
            hb.hold(rel, 100 + w, 10, 1 << 20);
            { HoldBack::Access a(hb, rel); std::ofstream(a.path(), std::ios::app) << "x"; }
            hb.touch(rel, 100 + w, 10);
            cm.protect_before_write(rel);
            (void)cm.oldest_copy(rel);
        }
    });
    th.emplace_back([&] { while (!stop) { hb.commit_due(0, [](long, long) { return true; }); hb.enforce_limit(4); } });
    th.emplace_back([&] { while (!stop) { hb.revert_owner(101); (void)hb.list(); (void)hb.count(); } });
    th.emplace_back([&] { while (!stop) { for (int i = 0; i < 16; ++i) cm.repair_path("f" + std::to_string(i), true, root + "/q"); } });
    std::this_thread::sleep_for(std::chrono::seconds(4)); stop = true;
    for (auto& x : th) x.join();
    std::cout << "tsan stress finished\n";
}
