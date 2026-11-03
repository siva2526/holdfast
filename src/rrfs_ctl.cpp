// rrfs_ctl.cpp
//
// CLI for the rrfs control interface.
//
//   rrfs_ctl <mountpoint> status
//   rrfs_ctl <mountpoint> checkpoints
//   rrfs_ctl <mountpoint> promote
//   rrfs_ctl <mountpoint> rollback <checkpoint_id>
//   rrfs_ctl <mountpoint> resume <pid>
//   rrfs_ctl <mountpoint> diff <checkpoint_id>
//   rrfs_ctl <mountpoint> watch [interval_seconds]
//
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

namespace {

std::string read_status(const std::string& mount) {
    std::ifstream in(mount + "/.rrfs_status");
    std::ostringstream ss;
    if (in) ss << in.rdbuf();
    return ss.str();
}

int send_command_silent(const std::string& mount, const std::string& cmd) {
    std::ofstream out(mount + "/.rrfs_control");
    if (!out) {
        std::cerr << "could not write " << mount << "/.rrfs_control "
                  << "(is rrfs mounted there?)\n";
        return 1;
    }
    out << cmd << "\n";
    return 0;
}

int send_command(const std::string& mount, const std::string& cmd) {
    if (send_command_silent(mount, cmd) != 0) return 1;
    std::cout << read_status(mount);
    return 0;
}

void print_usage(const char* prog) {
    std::cerr << "usage: " << prog
              << " <mountpoint> <status|checkpoints|promote|rollback|resume|release|discard|diff|watch> [args]\n"
              << "  status                  show current status, checkpoints, recent events\n"
              << "  checkpoints             list checkpoints only\n"
              << "  promote [recover]       manually take a checkpoint now; `recover` rebuilds it from the original-byte ring\n"
              << "  rollback <checkpoint_id> atomically restore that checkpoint\n"
              << "  resume <pid>            SIGCONT a process rrfs suspended\n"
              << "  release <pid>           false-positive override: commit its shelved writes, un-block and resume it\n"
              << "  diff <checkpoint_id>    show what a rollback to this checkpoint would\n"
              << "                          change -- modified/added/removed files -- WITHOUT\n"
              << "                          changing anything (read-only)\n"
              << "  watch [interval_sec]    poll status every N seconds (default 2)\n";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mount = argv[1];
    std::string verb = argv[2];

    if (verb == "status") {
        std::cout << read_status(mount);
        return 0;
    }

    if (verb == "checkpoints") {
        std::string s = read_status(mount);
        auto start = s.find("checkpoints (oldest first):");
        auto end = s.find("\nrecent events:");
        if (start == std::string::npos) {
            std::cerr << "could not parse status output\n";
            return 1;
        }
        std::cout << s.substr(start, end == std::string::npos ? std::string::npos
                                                                : end - start);
        return 0;
    }

    if (verb == "promote") {
        // `promote recover`: checkpoint rebuilt from the original-byte ring (what the pre-damage tree looked like), not a copy of the live tree
        return send_command(mount, (argc > 3 && std::string(argv[3]) == "recover") ? "PROMOTE recover" : "PROMOTE");
    }

    if (verb == "rollback") {
        if (argc < 4) {
            std::cerr << "rollback requires a checkpoint id (see 'checkpoints')\n";
            return 1;
        }
        return send_command(mount, std::string("ROLLBACK ") + argv[3]);
    }

    if (verb == "discard") {
        if (argc < 4) { std::cerr << "discard requires a pid (or the word cluster)\n"; return 1; }
        return send_command(mount, std::string("DISCARD ") + argv[3]);
    }

    if (verb == "release") {
        if (argc < 4) { std::cerr << "release requires a pid\n"; return 1; }
        return send_command(mount, std::string("RELEASE ") + argv[3]);
    }
    if (verb == "resume") {
        if (argc < 4) {
            std::cerr << "resume requires a pid (see 'status')\n";
            return 1;
        }
        return send_command(mount, std::string("RESUME ") + argv[3]);
    }

    if (verb == "diff") {
        if (argc < 4) {
            std::cerr << "diff requires a checkpoint id (see 'checkpoints')\n";
            return 1;
        }
        if (send_command_silent(mount, std::string("DIFF ") + argv[3]) != 0) return 1;
        std::string s = read_status(mount);
        auto start = s.find("diff vs ");
        auto end = s.find("\nsuspended pids:");
        if (start == std::string::npos) {
            std::cerr << "could not parse diff output\n";
            return 1;
        }
        std::cout << s.substr(start, end == std::string::npos ? std::string::npos
                                                                : end - start);
        return 0;
    }

    if (verb == "watch") {
        int interval = argc >= 4 ? std::atoi(argv[3]) : 2;
        if (interval <= 0) interval = 2;
        while (true) {
            std::cout << "\033[2J\033[H"; // clear screen
            std::cout << "rrfs watch (mount=" << mount << ", every " << interval << "s, "
                       << "Ctrl-C to stop)\n\n";
            std::cout << read_status(mount);
            std::cout.flush();
            std::this_thread::sleep_for(std::chrono::seconds(interval));
        }
    }

    print_usage(argv[0]);
    return 1;
}
