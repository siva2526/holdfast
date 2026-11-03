// tests/test_anomaly_engine.cpp -- unit tests for AnomalyEngine.
//
// Case 7 ("benign burst") is a regression test for a real
// false-positive bug found by an independent audit: the engine used
// to add burst credit for every write CALL regardless of content, so
// an ordinary `cp` of one large file (many calls, one path) or a
// `tar -x` of many small plain-text files (many paths, ordinary
// content) both crossed the default threshold and got the process
// frozen with SIGSTOP. Confirmed live against `cp`, `dd`, and `tar`
// on a real mount; see AUDIT_REPORT.pdf Section 3 (B1) and
// audit/expA.sh for the end-to-end reproduction. This test is the
// unit-level guard so the regression can't silently reappear.
#include "anomaly_engine.hpp"
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>

int main() {
    // A single low-entropy, non-bursty, no-extension-change write
    // should not move the score meaningfully.
    {
        AnomalyEngine ae;
        double s = ae.record_write(/*pid=*/1, "f1", /*entropy=*/3.0,
                                    /*extension_changed=*/false);
        assert(s < ae.promote_threshold);
    }

    // High entropy alone, once, should not cross the default threshold
    // -- the engine is designed to require fused signals, mirroring
    // Gap 1 (no single evadable signal should be sufficient).
    {
        AnomalyEngine ae;
        double s = ae.record_write(2, "f2", 7.99, false);
        assert(s < ae.promote_threshold);
    }

    // Repeated high-entropy writes to many distinct files from the
    // same pid, combined with extension churn, SHOULD cross the
    // threshold -- this is the ransomware-like pattern.
    {
        AnomalyEngine ae;
        double last = 0.0;
        for (int i = 0; i < 10; ++i) {
            last = ae.record_write(3, "f" + std::to_string(i), 7.9, true);
        }
        assert(last >= ae.promote_threshold);
    }

    // Scores are tracked per-pid: a noisy process shouldn't move
    // another process's score.
    {
        AnomalyEngine ae;
        for (int i = 0; i < 10; ++i) ae.record_write(10, "f" + std::to_string(i), 7.9, true);
        double innocent = ae.current_score(11);
        assert(innocent == 0.0);
    }

    // reset() clears accumulated score for a pid.
    {
        AnomalyEngine ae;
        for (int i = 0; i < 10; ++i) ae.record_write(20, "f" + std::to_string(i), 7.9, true);
        assert(ae.current_score(20) > 0.0);
        ae.reset(20);
        assert(ae.current_score(20) == 0.0);
    }

    // Score decays over time when a process goes quiet.
    {
        AnomalyEngine ae;
        ae.decay_per_second = 100.0; // fast decay for a snappy test
        ae.record_write(30, "f30", 7.99, false);
        double before = ae.current_score(30);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        double after = ae.current_score(30);
        assert(after <= before);
    }

    // *** Regression test for the audited false-positive bug ***
    // 20 distinct files, ordinary plain-text content (well below the
    // entropy high-water mark), no renames: this is `tar -x` of a
    // benign archive or a shell loop writing log files. It must NOT
    // cross the default threshold, no matter how many distinct files
    // are touched, because none of the individual events carries a
    // corroborating signal.
    {
        AnomalyEngine ae;
        double last = 0.0;
        for (int i = 0; i < 20; ++i) {
            last = ae.record_write(40, "benign" + std::to_string(i), /*entropy=*/3.8,
                                    /*extension_changed=*/false);
        }
        assert(last < ae.promote_threshold);
    }

    // Companion case: repeated writes to the SAME path (an ordinary
    // `cp` of one large file via many small chunks) must not
    // accumulate burst credit either, since it is only ever one
    // distinct path regardless of call count.
    {
        AnomalyEngine ae;
        double last = 0.0;
        for (int i = 0; i < 50; ++i) {
            last = ae.record_write(41, "onefile.txt", /*entropy=*/3.8,
                                    /*extension_changed=*/false);
        }
        assert(last < ae.promote_threshold);
    }

    std::cout << "test_anomaly_engine: ALL PASSED\n";
        // Destructive-vs-creative tracking: fresh high-entropy paths are
    // remembered per PID, consumed once, and cleared by reset().
    {
        AnomalyEngine ae;
        assert(!ae.has_fresh_high_entropy(50));
        ae.note_fresh_high_entropy(50, "tmp1");
        assert(ae.has_fresh_high_entropy(50));
        assert(!ae.has_fresh_high_entropy(51));            // per-PID isolation
        assert(ae.take_fresh_high_entropy(50, "tmp1"));
        assert(!ae.take_fresh_high_entropy(50, "tmp1"));   // consumed
        ae.mark_destroyed(50, "victim");
        assert(ae.is_destroyed(50, "victim") && !ae.is_destroyed(50, "other"));
        ae.reset(50);
        assert(!ae.is_destroyed(50, "victim"));
    }

        // Slow-burn: paced events below burst/decay still trip the long-window signal.
    {
        AnomalyEngine ae; ae.slow_burn_files = 5;
        double last = 0;
        for (int i = 0; i < 5; ++i) {
            last = ae.record_write(60, "slow" + std::to_string(i), 7.9, false);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        assert(last >= ae.promote_threshold);
        // Benign-looking events (not corroborated) never count toward it.
        AnomalyEngine b; b.slow_burn_files = 3;
        for (int i = 0; i < 20; ++i) assert(b.record_write(61, "n" + std::to_string(i), 3.0, false) < b.promote_threshold);
    }
    // type_changed: counts once per path per window and corroborates.
    {
        AnomalyEngine ae;
        double s1 = ae.record_write(70, "a.jpg", 0.0, false, true);
        double s2 = ae.record_write(70, "a.jpg", 0.0, false, true);
        assert(s1 > 2.5 && s2 <= s1);           // second event on same path adds nothing (modulo decay)
    }

    // ambiguous tracking: distinct files, hold while recent, release after defer window.
    {
        AnomalyEngine ae;
        for (int i = 0; i < 7; ++i) ae.note_ambiguous(80, "f" + std::to_string(i));
        assert(!ae.ambiguous_hold(80, 60000, 8));
        ae.note_ambiguous(80, "f3");                       // repeat, still 7 distinct
        assert(!ae.ambiguous_hold(80, 60000, 8));
        assert(ae.note_ambiguous(80, "f7") == 8);
        assert(ae.ambiguous_hold(80, 60000, 8));
        assert(!ae.ambiguous_hold(80, 0, 8));              // defer window of 0 ms = released
        assert(!ae.ambiguous_hold(81, 60000, 8));          // other pids unaffected
    }

    // is_created is non-consuming; take_created consumes.
    {
        AnomalyEngine ae;
        ae.note_created(90, "tmp1");
        assert(ae.is_created(90, "tmp1") && ae.is_created(90, "tmp1"));
        assert(!ae.is_created(91, "tmp1"));
        assert(ae.take_created(90, "tmp1"));
        assert(!ae.is_created(90, "tmp1"));
    }

    // content_files counts distinct content-evidence paths only; extension churn alone gives none.
    {
        AnomalyEngine ae;
        for (int i = 0; i < 10; ++i) ae.record_write(100, "r" + std::to_string(i), 0.0, true);   // renames only
        assert(ae.current_score(100) >= ae.promote_threshold && ae.content_files(100) == 0);       // soft-only situation
        ae.record_write(100, "c1", 8.0, false);
        ae.record_write(100, "c1", 8.0, false);
        assert(ae.content_files(100) == 1);
        ae.record_write(100, "c2", 0.0, false, true);
        assert(ae.content_files(100) == 2);
        assert(ae.soft_alert_due(100, std::chrono::seconds(60)));
        assert(!ae.soft_alert_due(100, std::chrono::seconds(60)));
    }
    // cluster hold needs enough files AND enough distinct processes; global needs files only.
    {
        AnomalyEngine ae;
        for (int i = 0; i < 8; ++i) ae.note_cluster("/usr/bin/x", 200, "f" + std::to_string(i));   // one pid: no hold
        assert(ae.cluster_hold(200, 60000).empty());
        for (int i = 0; i < 8; ++i) ae.note_cluster("/usr/bin/y", 300 + i, "g" + std::to_string(i)); // 8 files, 8 pids
        assert(ae.cluster_hold(303, 60000) == "/usr/bin/y");
        assert(ae.cluster_hold(303, 0).empty());                                                      // defer expired
        assert(ae.cluster_hold(999, 60000).empty());                                                  // non-member
        for (int i = 0; i < 16; ++i) ae.note_cluster("*", 500, "h" + std::to_string(i));
        assert(ae.cluster_hold(500, 60000) == "*");
    }

    return 0;
}
