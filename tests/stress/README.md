Stand-alone ThreadSanitizer stress programs (not part of `ctest`). From the repository root:

    g++ -std=c++17 -fsanitize=thread -O1 -Iinclude tests/stress/tsan_holdback_stress.cpp src/holdback.cpp src/canary_manager.cpp -lpthread -o /tmp/tsan_hold && /tmp/tsan_hold
    g++ -std=c++17 -fsanitize=thread -O1 -Iinclude tests/stress/tsan_stress.cpp src/canary_manager.cpp src/anomaly_engine.cpp src/ext_tracker.cpp src/event_log.cpp -lpthread -o /tmp/tsan_engine && /tmp/tsan_engine
