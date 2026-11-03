cmake_minimum_required(VERSION 3.10)
project(rrfs CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

include_directories(${CMAKE_SOURCE_DIR}/include ${FUSE3_INCLUDE_DIRS})
link_directories(${FUSE3_LIBRARY_DIRS})
add_compile_options(${FUSE3_CFLAGS_OTHER})

set(CORE_SOURCES
    src/anomaly_engine.cpp
    src/canary_manager.cpp
    src/config.cpp
    src/event_log.cpp
    src/ext_tracker.cpp
    src/holdback.cpp
)

add_executable(rrfs_fuse src/rrfs_fuse.cpp ${CORE_SOURCES})
target_link_libraries(rrfs_fuse ${FUSE3_LIBRARIES} pthread)

add_executable(rrfs_ctl src/rrfs_ctl.cpp)

# --- Test suite (no FUSE mount required -- exercises the core logic
#     directly) --------------------------------------------------------
enable_testing()

add_executable(test_entropy tests/test_entropy.cpp)

add_executable(test_anomaly_engine tests/test_anomaly_engine.cpp src/anomaly_engine.cpp)

add_executable(test_canary_manager tests/test_canary_manager.cpp src/canary_manager.cpp)

add_executable(test_ext_tracker tests/test_ext_tracker.cpp src/ext_tracker.cpp)

add_executable(test_diff tests/test_diff.cpp src/canary_manager.cpp)

add_executable(test_auto_checkpoint_recovery tests/test_auto_checkpoint_recovery.cpp src/canary_manager.cpp)

add_executable(test_promote_rate_limit tests/test_promote_rate_limit.cpp src/canary_manager.cpp)
target_link_libraries(test_promote_rate_limit pthread)

add_executable(test_auto_checkpoint_rename_chain tests/test_auto_checkpoint_rename_chain.cpp src/canary_manager.cpp)

add_executable(test_checkpoint_retention tests/test_checkpoint_retention.cpp src/canary_manager.cpp)
target_link_libraries(test_checkpoint_retention pthread)

add_executable(test_content_delta tests/test_content_delta.cpp)

add_executable(test_holdback tests/test_holdback.cpp src/holdback.cpp src/canary_manager.cpp)
target_link_libraries(test_holdback pthread)

add_test(NAME test_entropy COMMAND test_entropy)
add_test(NAME test_anomaly_engine COMMAND test_anomaly_engine)
add_test(NAME test_canary_manager COMMAND test_canary_manager)
add_test(NAME test_ext_tracker COMMAND test_ext_tracker)
add_test(NAME test_diff COMMAND test_diff)
add_test(NAME test_auto_checkpoint_recovery COMMAND test_auto_checkpoint_recovery)
add_test(NAME test_promote_rate_limit COMMAND test_promote_rate_limit)
add_test(NAME test_auto_checkpoint_rename_chain COMMAND test_auto_checkpoint_rename_chain)
add_test(NAME test_checkpoint_retention COMMAND test_checkpoint_retention)
add_test(NAME test_content_delta COMMAND test_content_delta)
add_test(NAME test_holdback COMMAND test_holdback)
