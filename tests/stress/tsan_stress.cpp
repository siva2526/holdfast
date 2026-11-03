#include "canary_manager.hpp"
#include "anomaly_engine.hpp"
#include "ext_tracker.hpp"
#include "event_log.hpp"
#include <thread>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdlib>
int main() {
    system("rm -rf /tmp/holdfast_tsan && mkdir -p /tmp/holdfast_tsan/b");
    for (int i = 0; i < 20; ++i) std::ofstream("/tmp/holdfast_tsan/b/f" + std::to_string(i)) << "data" << i;
    CanaryManager cm("/tmp/holdfast_tsan/b", "/tmp/holdfast_tsan/c", "/tmp/holdfast_tsan/k", 4); cm.init();
    AnomalyEngine ae; ExtensionTracker et; EventLog lg("/tmp/holdfast_tsan/ev.log");
    std::vector<std::thread> th;
    for (int t = 0; t < 4; ++t) th.emplace_back([&, t] { for (int i = 0; i < 200; ++i) {
        std::string p = "f" + std::to_string((i + t) % 20);
        cm.protect_before_write(p); ae.record_write(100 + t, p, 7.9, et.on_write(p));
        et.on_rename(p, p + ".x"); lg.log("write", 100 + t, p, 7.9, 1.0); } });
    th.emplace_back([&] { for (int i = 0; i < 5; ++i) { cm.promote_checkpoint("auto", 1, 1.0); } });
    th.emplace_back([&] { for (int i = 0; i < 30; ++i) { auto l = cm.list_checkpoints(); if (!l.empty()) cm.diff_against(l.back().id); lg.tail(5); } });
    for (auto& x : th) x.join();
    std::cout << "stress finished\n";
}
